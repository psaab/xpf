package config

import (
	"testing"
)

// #15038 (A21-01): Junos ip-monitoring targets carry `interface <unit>` and
// `secondary-ip-address <addr>` so the probe can be sent from the address the
// probing node actually holds on that unit (the VIP on the primary, the
// secondary address on the secondary). Without the model the compiled target
// is address-only and the cluster monitor probes from an unbound socket.
func TestIPMonitoringTargetInterfaceSecondaryIP_15038(t *testing.T) {
	tree := hierTree(t, `chassis {
	cluster {
		cluster-id 1;
		node 0;
		authentication-key aaaaaaaaaaaaaaaa;
		redundancy-group 1 {
			ip-monitoring {
				global-weight 255;
				family inet {
					10.0.0.1 {
						weight 255;
						interface reth0.0;
						secondary-ip-address 10.0.0.3;
					}
				}
			}
		}
	}
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected ip-monitoring interface/secondary-ip-address: %v", err)
	}
	rg := findRG13090(t, cfg, 1)
	if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
		t.Fatalf("targets = %+v, want one target", rg.IPMonitoring)
	}
	tg := rg.IPMonitoring.Targets[0]
	if tg.Address != "10.0.0.1" || tg.Weight != 255 {
		t.Fatalf("target = %+v, want address 10.0.0.1 weight 255", tg)
	}
	if tg.Interface != "reth0.0" {
		t.Fatalf("target Interface = %q, want %q", tg.Interface, "reth0.0")
	}
	if tg.SecondaryIPAddress != "10.0.0.3" {
		t.Fatalf("target SecondaryIPAddress = %q, want %q", tg.SecondaryIPAddress, "10.0.0.3")
	}
}

// The packed spelling must compile to the same target as the block spelling.
func TestIPMonitoringTargetInterfaceSecondaryIPPacked_15038(t *testing.T) {
	for _, text := range []string{
		`chassis { cluster { cluster-id 1; node 0; authentication-key aaaaaaaaaaaaaaaa; redundancy-group 1 { ip-monitoring { global-weight 255; family inet 10.0.0.1 weight 255 interface reth0.0 secondary-ip-address 10.0.0.3; } } } }`,
		`chassis { cluster { cluster-id 1; node 0; authentication-key aaaaaaaaaaaaaaaa; redundancy-group 1 { ip-monitoring { global-weight 255; family inet { 10.0.0.1 { weight 255; interface reth0.0; secondary-ip-address 10.0.0.3; } } } } } }`,
	} {
		cfg := compileText(t, text)
		if cfg == nil || cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) != 1 {
			t.Fatalf("compile failed for %q", text)
		}
		rg := cfg.Chassis.Cluster.RedundancyGroups[0]
		if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
			t.Fatalf("targets lost for %q: %+v", text, rg.IPMonitoring)
		}
		tg := rg.IPMonitoring.Targets[0]
		if tg.Interface != "reth0.0" || tg.SecondaryIPAddress != "10.0.0.3" || tg.Weight != 255 {
			t.Fatalf("target = %+v for %q, want interface reth0.0 secondary 10.0.0.3 weight 255", tg, text)
		}
	}
}
