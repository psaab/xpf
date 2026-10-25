package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16590 acceptance at the readiness layer: a disabled tagged unit's child
// being DOWN must no longer block RG takeover readiness (its VIP is not in
// the set at all), while the enabled sibling still gates readiness.

func TestCheckVIPReadinessDisabledUnit16590(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0", RedundancyGroup: 1, VlanTagging: true,
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
						80: {Number: 80, VlanID: 80, Disable: true, Addresses: []string{"172.16.80.8/24"}},
					},
				},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
			},
		},
	}
	// Enabled child up, disabled child down (networkd always-down).
	links := map[string]*testLink{
		"ge-0-0-2.50": newTestLink("ge-0-0-2.50", true),
		"ge-0-0-2.80": newTestLink("ge-0-0-2.80", false),
	}
	ready, reasons := checkVIPReadinessForConfig(cfg, 1, mockLinkByName(links))
	if !ready {
		t.Fatalf("disable-unit80=true arm must be ready, got reasons %v", reasons)
	}

	// Control: unit 80 enabled and down -> not ready.
	cfg.Interfaces.Interfaces["reth0"].Units[80].Disable = false
	ready, reasons = checkVIPReadinessForConfig(cfg, 1, mockLinkByName(links))
	if ready {
		t.Fatalf("enabled down unit must block readiness, got ready (reasons %v)", reasons)
	}
}
