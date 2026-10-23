package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15946 H24-01: RG0 must not sweep default-0/member interfaces.
func TestRGZeroOwnership15946(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth1":    {Name: "reth1", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.1.1/24"}}}},
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth1", Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.2.1/24"}}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.9.1/24"}}}},
	}}}
	if rgHasRETH(cfg, 0) {
		t.Fatal("rgHasRETH(0) must be false")
	}
	if got := haRoutingRequirementsForRG(cfg, 0); len(got) != 0 {
		t.Fatalf("RG0 requirements must be empty, got %+v", got)
	}
	if !rgHasRETH(cfg, 1) {
		t.Fatal("rgHasRETH(1) must be true")
	}
}
