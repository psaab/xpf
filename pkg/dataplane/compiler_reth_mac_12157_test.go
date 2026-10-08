package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCompilerRethRecoveryUsesIndexedMACAndExcludesNamedSibling_12157(t *testing.T) {
	indexedMAC := config.RethVirtualMAC(1, 1, 1, 0)
	legacyMAC := config.RethVirtualMAC(1, 1, 0, 0)
	interfaces := []net.Interface{
		{Name: "reth-sibling-member", HardwareAddr: legacyMAC},
		{Name: "enp8s1", HardwareAddr: indexedMAC},
	}
	excluded := map[string]struct{}{"reth-sibling-member": {}, "reth-target-member": {}}

	got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded)
	if got == nil || got.Name != "enp8s1" {
		t.Fatalf("compiler recovered %v, want the indexed-MAC interface enp8s1", got)
	}
}

func TestCompilerRethRecoveryUsesLegacyMACOnlyWhenUnique_12157(t *testing.T) {
	indexedMAC := config.RethVirtualMAC(1, 1, 1, 0)
	legacyMAC := config.RethVirtualMAC(1, 1, 0, 0)
	excluded := map[string]struct{}{"reth-sibling-member": {}, "reth-target-member": {}}

	interfaces := []net.Interface{
		{Name: "reth-sibling-member", HardwareAddr: legacyMAC},
		{Name: "enp8s1", HardwareAddr: legacyMAC},
	}
	got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded)
	if got == nil || got.Name != "enp8s1" {
		t.Fatalf("compiler legacy-MAC recovery returned %v, want enp8s1 after excluding its sibling", got)
	}

	interfaces = append(interfaces, net.Interface{Name: "enp8s2", HardwareAddr: legacyMAC})
	if got := findRethMemberByMAC(indexedMAC, legacyMAC, interfaces, excluded); got != nil {
		t.Fatalf("compiler selected ambiguous legacy-MAC interface %q, want no recovery", got.Name)
	}
}
