package config

import (
	"strings"
	"testing"
)

// #2823: the Junos `persistent-nat permit` statement is a three-way enum
// (any-remote-host | target-host | target-host-port). These tests use the
// production ParseSetCommand + SetPath path (buildTree), never NewParser
// (the flat-set gotcha in CLAUDE.md), and verify the parse, the default
// mode, and the schema commit-check.

func persistentNATSet(permit string) []string {
	lines := []string{
		"set security nat source pool p-src address 203.0.113.10",
	}
	if permit != "" {
		lines = append(lines,
			"set security nat source pool p-src persistent-nat permit "+permit)
	} else {
		// Materialize the persistent-nat stanza WITHOUT a permit to
		// exercise the default-mode path.
		lines = append(lines,
			"set security nat source pool p-src persistent-nat inactivity-timeout 300")
	}
	return lines
}

func compilePersistentPool(t *testing.T, permit string) *PersistentNATConfig {
	t.Helper()
	tree := buildTree(t, persistentNATSet(permit))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p-src"]
	if pool == nil {
		t.Fatal("pool p-src not compiled")
	}
	if pool.PersistentNAT == nil {
		t.Fatal("PersistentNAT not compiled")
	}
	return pool.PersistentNAT
}

func TestPersistentNATPermitParsesThreeWayEnum(t *testing.T) {
	cases := map[string]PersistentNATPermit{
		"any-remote-host":  PersistentNATPermitAnyRemoteHost,
		"target-host":      PersistentNATPermitTargetHost,
		"target-host-port": PersistentNATPermitTargetHostPort,
	}
	for in, want := range cases {
		got := compilePersistentPool(t, in).Permit
		if got != want {
			t.Errorf("permit %q -> %q, want %q", in, got, want)
		}
	}
}

// The default (persistent-nat configured with NO permit) must be
// target-host-port: the pre-#2823 binary model keyed the lease by
// (dst_ip, dst_port) when the flag was false, and #2819 created the
// binding regardless. Defaulting to target-host-port keeps that behavior
// byte-identical (back-compat).
func TestPersistentNATPermitDefaultIsTargetHostPort(t *testing.T) {
	got := compilePersistentPool(t, "").Permit
	if got != PersistentNATPermitTargetHostPort {
		t.Fatalf("default permit = %q, want target-host-port", got)
	}
}

func TestPersistentNATPermitSchemaValidates(t *testing.T) {
	for _, permit := range []string{"any-remote-host", "target-host", "target-host-port"} {
		tree := buildTree(t, persistentNATSet(permit))
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("SchemaValidate rejected valid permit %q: %v", permit, err)
		}
	}
}

// The three permit values must be offered by value-slot completion so
// `set ... persistent-nat permit ?` lists them (#2823).
func TestPersistentNATPermitSchemaCompletes(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"security", "nat", "source", "pool", "p-src", "persistent-nat", "permit"}, nil)
	for _, want := range []string{"any-remote-host", "target-host", "target-host-port"} {
		if !containsCompletionName(results, want) {
			t.Errorf("permit completion missing %q; got %v", want, completionNames(results))
		}
	}
}

func TestPersistentNATPermitSchemaRejectsInvalid(t *testing.T) {
	tree := buildTree(t, persistentNATSet("bogus-scope"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("SchemaValidate must reject an invalid persistent-nat permit value")
	}
	if !strings.Contains(err.Error(), "bogus-scope") {
		t.Fatalf("error should name the bad value, got: %v", err)
	}
}
