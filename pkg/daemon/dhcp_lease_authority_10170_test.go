package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDHCPLeaseScopeAuthorityIgnoresRGZero10170(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 0},
	}}}
	if rg, ok := dhcpLeaseRGForInterface(cfg, "reth0.80", cfg.RethRGOwners()); ok || rg != 0 {
		t.Fatalf("RG0 must not become an authoritative HA scope: rg=%d ok=%v", rg, ok)
	}
}
