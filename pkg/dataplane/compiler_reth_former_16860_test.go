package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCompilerRethRecoveryExcludesConfiguredStandalone16860: a configured
// standalone interface carrying a stale RETH virtual MAC must not be returned
// as the missing member's recovery candidate (#16860).
func TestCompilerRethRecoveryExcludesConfiguredStandalone16860(t *testing.T) {
	indexedMAC := config.RethVirtualMAC(1, 1, 1, 0)
	legacyMAC := config.RethVirtualMAC(1, 1, 0, 0)
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1"},
		"ge-0/0/5": {Name: "ge-0/0/5", RedundantParent: "reth1"},
		"reth1":    {Name: "reth1", RedundancyGroup: 1},
	}}}
	excluded := cfg.ConfiguredLinuxNames()
	interfaces := []net.Interface{
		{Name: "ge-0-0-1", HardwareAddr: indexedMAC},
	}
	if got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded); got != nil {
		t.Fatalf("compiler recovered configured standalone %q, want nil", got.Name)
	}
	// Control: an unconfigured kernel-named device with the same MAC is
	// still recoverable.
	interfaces = append(interfaces, net.Interface{Name: "enp8s0", HardwareAddr: indexedMAC})
	if got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded); got == nil || got.Name != "enp8s0" {
		t.Fatalf("compiler recovery control = %v, want enp8s0", got)
	}
}

// TestCompilerRethRecoveryExcludesPendingFormerMember17890 protects an
// unconfigured former member from the compiler's missing-member search while
// its failed MAC restoration is pending.
func TestCompilerRethRecoveryExcludesPendingFormerMember17890(t *testing.T) {
	indexedMAC := config.RethVirtualMAC(1, 1, 1, 0)
	legacyMAC := config.RethVirtualMAC(1, 1, 0, 0)
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/3": {Name: "ge-0/0/3", RedundantParent: "reth1"},
			"reth1":    {Name: "reth1", RedundancyGroup: 1},
		}},
	}
	pending := map[string]struct{}{"ge-0-0-1": {}}
	interfaces := []net.Interface{{Name: "ge-0-0-1", HardwareAddr: indexedMAC}}

	if got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, cfg.ConfiguredLinuxNames()); got == nil {
		t.Fatal("fixture must show the unconfigured former is otherwise recoverable")
	}
	manager := &Manager{}
	SetRethRecoveryExclusions(manager, pending)
	excluded := rethRecoveryExcludedNames(cfg, rethRecoveryExclusionsFor(manager))
	if _, configured := cfg.Interfaces.Interfaces["ge-0/0/1"]; configured {
		t.Fatal("fixture error: former member is configured")
	}
	if got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded); got != nil {
		t.Fatalf("compiler recovered pending former member %q, want no candidate", got.Name)
	}
}
