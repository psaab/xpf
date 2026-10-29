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

// #17749: under #6515 REPLACE semantics an interface-level stanza
// REPLACES the zone set entirely. When zone `all` is replaced on EVERY
// member interface by a non-SSH stanza, no interface effectively
// admits SSH, so the zone-level branch must not warn "zone admits SSH".
// RED pre-fix: the zone-level key is checked independently and warns.
func TestSSHUnmanagedAdvisory16737_SilentWhenAllMembersReplaceZoneAll(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.2/24",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
		"set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ping",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("every member interface replaces zone `all` with non-SSH: no effective SSH admission, must not warn; warnings=%q", cfg.Warnings)
	}
}

// #17749 / #3720 control: a physical interface-level override replaces
// the zone set on each configured unit, so the zone's `all` must not
// trigger an advisory when the physical override admits only `ping`.
func TestSSHUnmanagedAdvisory16737_SilentWhenPhysicalOverrideReplacesZoneAll(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.0.2.2/24",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ping",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("physical override replaces zone `all` with non-SSH on all units; must not warn; warnings=%q", cfg.Warnings)
	}
}

// #17749 fold: when unit 0 is absent, the physical-parent key remains a
// distinct candidate and uses the zone set even if unit 1 replaces it. The
// companion userspace regression injects the parent's live address into an
// enforcement snapshot and verifies that the builder binds it to this view.
func TestSSHUnmanagedAdvisory16737_WarnsForDistinctPhysicalParentCarrier(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.1 host-inbound-traffic system-services ping",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("distinct physical parent uses zone-level `all` while unit 1 replaces it; must warn; warnings=%q", cfg.Warnings)
	}
}

// #17749 control: a bare physical member fans down to its configured
// units, but a unit quarantined by another zone must not make the first
// zone appear to admit SSH.
func TestSSHUnmanagedAdvisory16737_SkipsForeignUnitOfBareMember(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.0.2.2/24",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
		"set security zones security-zone untrust interfaces ge-0/0/0.1",
	}))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if _, quarantined := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.1"]; !quarantined {
		t.Fatalf("fixture must quarantine the unit assigned under both a bare and unit-specific zone member")
	}
	cfg.Warnings = nil
	appendSSHUnmanagedAdvisory16737Locked(cfg, compileOpts{})
	if hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("SSH on a quarantined foreign unit must not make trust's narrowed local unit appear to admit SSH; warnings=%q", cfg.Warnings)
	}
}

// #17749 fold: lifeline (management/fabric) members are excluded from
// host-inbound deny scoping by enforcement (zones_host_inbound.go skips
// them before per-interface resolution), so a zone whose ONLY member is
// the fixed lifeline fxp0 must not be reported as SSH-admitting.
func TestSSHUnmanagedAdvisory16737_SilentForLifelineOnlyAdmission(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces fxp0 unit 0 family inet address 10.9.0.1/24",
		"set security zones security-zone mgmt host-inbound-traffic system-services ssh",
		"set security zones security-zone mgmt interfaces fxp0.0",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if hasSSHUnmanagedAdvisory16737(cfg, "mgmt") {
		t.Fatalf("lifeline-only admission must not warn: host-inbound deny is never applied on fxp0; warnings=%q", cfg.Warnings)
	}
}

// #17749 fold control: the same ssh admission with an ordinary member
// alongside the lifeline still warns.
func TestSSHUnmanagedAdvisory16737_WarnsWhenLifelineHasOrdinaryMember(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces fxp0 unit 0 family inet address 10.9.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone mgmt host-inbound-traffic system-services ssh",
		"set security zones security-zone mgmt interfaces fxp0.0",
		"set security zones security-zone mgmt interfaces ge-0/0/0.0",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasSSHUnmanagedAdvisory16737(cfg, "mgmt") {
		t.Fatalf("ordinary member inherits ssh admission; must warn; warnings=%q", cfg.Warnings)
	}
}

// #17749 control: the zone stanza remains zone-scope when a member
// inherits it (no override) — or when the override itself admits SSH —
// so the advisory must still fire in both shapes.
func TestSSHUnmanagedAdvisory16737_WarnsWhenZoneAllStillReachesAMember(t *testing.T) {
	t.Run("member inherits zone set", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.2/24",
			"set security zones security-zone trust host-inbound-traffic system-services all",
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
			"set security zones security-zone trust interfaces ge-0/0/1.0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if !hasSSHUnmanagedAdvisory16737(cfg, "trust") {
			t.Fatalf("a member without override still inherits zone `all` (admits ssh); warnings=%q", cfg.Warnings)
		}
	})
	t.Run("override admits ssh", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
			"set security zones security-zone trust host-inbound-traffic system-services ping",
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if !hasSSHUnmanagedAdvisory16737(cfg, "trust") {
			t.Fatalf("an override admitting ssh must warn; warnings=%q", cfg.Warnings)
		}
	})
	t.Run("no zone members and no overrides", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set security zones security-zone trust host-inbound-traffic system-services all",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if !hasSSHUnmanagedAdvisory16737(cfg, "trust") {
			t.Fatalf("zone-set admission with no narrowed reach must warn; warnings=%q", cfg.Warnings)
		}
	})
}

func hasSSHUnmanagedAdvisory16737(cfg *Config, zone string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no `system services ssh` stanza") && strings.Contains(w, `"`+zone+`"`) {
			return true
		}
	}
	return false
}
