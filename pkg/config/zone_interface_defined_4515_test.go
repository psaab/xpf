package config

import (
	"strings"
	"testing"
)

// TestZoneInterfaceUndefinedFailsCommit is the fail-on-revert guard for the
// ps-review-002 F6 parity gap (#4515): a `security zones security-zone <z>
// interfaces <if>` entry that names an interface which is NOT defined under
// `interfaces {}` (nor a daemon-materialized lo0 / IPsec secure-tunnel) MUST be
// hard-rejected at commit, exactly as Junos rejects it. Without
// validateZoneInterfaceDefinedStrict (or its dispatch in runUniformGates) this
// config compiles cleanly — the pre-#4515 behavior was a warn-only advisory,
// and the daemon then brought the absent interface DOWN, so the zone member
// silently carried no traffic with no commit-time signal. The error must name
// both the zone and the offending interface.
func TestZoneInterfaceUndefinedFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		// ge-0/0/99 is a typo — no such interface is configured.
		"set security zones security-zone untrust interfaces ge-0/0/99.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a zone referencing an undefined interface, got nil error")
	}
	for _, want := range []string{"untrust", "ge-0/0/99.0", "not defined under"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestZoneInterfaceUndefinedLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path downgrades the undefined-interface rejection to a
// warning instead of failing the compile, so an already-persisted or
// peer-synced config an older binary accepted still boots (#4515 / #1960
// no-brick). Runtime behavior is unchanged on that path (the unresolved member
// carries no traffic), just with an operator-visible warning.
func TestZoneInterfaceUndefinedLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/99.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a zone referencing an undefined interface: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone interface defined (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded zone-interface-defined warning, got warnings: %v", cfg.Warnings)
	}
}

// TestZoneInterfaceDefinedCommitsClean asserts the common case — every zone
// member is a configured interface — commits cleanly: the gate does not perturb
// a valid config (#4515 anti-over-reject).
func TestZoneInterfaceDefinedCommitsClean(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a valid config whose zone interfaces are all defined: %v", err)
	}
}

// TestZoneInterfaceLoopbackAcceptedWithoutExplicitDef is the F6 safeguard proof
// for the lo0 branch of the dynamic-interface union (#4515,
// zoneReferenceableInterfaceBases). A zone may reference lo0 (the always-present
// loopback, a reserved Junos interface) with NO explicit `set interfaces lo0`,
// so the promotion must NOT false-reject it (the #4191 over-rejection class).
func TestZoneInterfaceLoopbackAcceptedWithoutExplicitDef(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone host interfaces lo0.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a zone referencing lo0 without an explicit interfaces def: %v", err)
	}
}

// TestZoneInterfaceIPsecBindInterfaceAcceptedWithoutExplicitDef is the F6
// safeguard proof for the IPsec secure-tunnel branch of the dynamic-interface
// union (#4515). `bind-interface st0.0` materializes the st0 xfrmi device at
// apply time even with no explicit `set interfaces st0 unit 0`, so a zone that
// references st0.0 is a valid, daemon-materialized dynamic interface the
// promotion must NOT false-reject (the #4191 over-rejection class). Covering the
// base st0 admits every unit of the bound tunnel.
func TestZoneInterfaceIPsecBindInterfaceAcceptedWithoutExplicitDef(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a zone referencing an IPsec bind-interface secure tunnel: %v", err)
	}
}

func TestZoneInterfaceAbsentLogicalUnitFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet sampling input",
		"set security zones security-zone trust interfaces ge-0/0/0.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject zone reference to absent logical unit 1")
	}
	for _, want := range []string{"trust", "ge-0/0/0.1", "logical unit", "not configured"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

func TestZoneInterfaceExistingLogicalUnitCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet sampling input",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a zone reference to defined logical unit 0: %v", err)
	}
}

func TestZoneInterfaceAbsentLogicalUnitWarnsOnLenientLoad(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet sampling input",
		"set security zones security-zone trust interfaces ge-0/0/0.1",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must warn rather than reject an absent zone unit: %v", err)
	}
	for _, want := range []string{
		"zone interface defined (downgraded to warning on tolerant path)",
		"trust", "ge-0/0/0.1", "logical unit",
	} {
		found := false
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no warning contains %q: %v", want, cfg.Warnings)
		}
	}
}
