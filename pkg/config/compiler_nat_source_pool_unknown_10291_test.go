// #10291: source-NAT pool properties were switched only for the five modeled
// leaves. Every other child, including valid Junos features that xpf does not
// implement and misspellings, fell through and committed with no effect.
//
// The compiler must preserve the authored leaf long enough for the strict gate
// to reject it by name. The tolerant path warns so an already-committed config
// still loads, while the five modeled leaves keep their existing semantics.
package config

import (
	"strings"
	"testing"
)

func sourcePoolUnknown10291Tree(t *testing.T, leaf string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set security nat source pool P1 address 203.0.113.5/32",
		"set security nat source pool P1 " + leaf,
	})
}

func TestSourceNATPoolUnsupportedLeavesRejected10291(t *testing.T) {
	cases := []struct {
		name  string
		leaf  string
		token string
	}{
		{name: "overflow-pool", leaf: "overflow-pool interface", token: "overflow-pool"},
		{name: "host-address-base", leaf: "host-address-base 10.0.0.0/24", token: "host-address-base"},
		{name: "address-pooling", leaf: "address-pooling paired", token: "address-pooling"},
		{name: "typo", leaf: "adress 198.51.100.7/32", token: "adress"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := sourcePoolUnknown10291Tree(t, tc.leaf)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("unsupported source-pool leaf %q committed cleanly", tc.token)
			} else if !strings.Contains(err.Error(), tc.token) || !strings.Contains(err.Error(), "#10291") {
				t.Fatalf("strict error = %q, want token %q and #10291", err, tc.token)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile rejected unsupported leaf %q: %v", tc.token, err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warnings, tc.token) || !strings.Contains(warnings, "#10291") {
				t.Fatalf("tolerant warnings = %q, want token %q and #10291", warnings, tc.token)
			}
			if pool := cfg.Security.NAT.SourcePools["P1"]; pool == nil {
				t.Fatal("tolerant compile dropped source pool P1")
			}
		})
	}
}

func TestSourceNATPoolSupportedLeavesCompileUnchanged10291(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool P1 address 203.0.113.5/32",
		"set security nat source pool P1 port range 5000 to 6000",
		"set security nat source pool P1 persistent-nat permit target-host",
		"set security nat source pool P1 persistent-nat inactivity-timeout 600",
		"set security nat source pool P1 port-overloading-factor 4",
		"set security nat source pool P1 routing-instance RI",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("the five modeled source-pool leaves must still compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["P1"]
	if pool == nil {
		t.Fatal("source pool P1 missing")
	}
	if len(pool.Addresses) != 1 || pool.Addresses[0] != "203.0.113.5/32" {
		t.Fatalf("source pool addresses = %#v, want the authored address", pool.Addresses)
	}
	if pool.PortLow != 5000 || pool.PortHigh != 6000 {
		t.Fatalf("source pool port range = %d-%d, want 5000-6000", pool.PortLow, pool.PortHigh)
	}
	if pool.PersistentNAT == nil || pool.PersistentNAT.Permit != PersistentNATPermitTargetHost || pool.PersistentNAT.InactivityTimeout != 600 {
		t.Fatalf("source pool persistent NAT = %#v, want target-host/600", pool.PersistentNAT)
	}
	if pool.PortOverloadingFactor != 4 {
		t.Fatalf("source pool port-overloading-factor = %d, want 4", pool.PortOverloadingFactor)
	}
	if pool.RoutingInstance != "RI" {
		t.Fatalf("source pool routing-instance = %q, want RI", pool.RoutingInstance)
	}
}
