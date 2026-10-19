package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15206 (A17-03): the daemon-side Kea belt. After
// resolveDHCPRethInterfaces, a group ref naming no configured interface
// or unit is still the verbatim phantom (`reth1.7`); handing it to Kea
// makes Kea refuse the whole family file. desiredStandaloneDHCPConfig
// must drop it (keeping real devices), and the shared active config must
// keep the authored ref (#9141 posture).
//
// FAIL-ON-REVERT: drop the FilterKeaInterfaces15206 calls in
// desiredStandaloneDHCPConfig and `reth1.7` survives below.

func phantomCfg15206(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set system services dhcp-local-server group good interface reth1.0",
		"set system services dhcp-local-server group good pool p1 subnet 10.0.61.0/24",
		"set system services dhcp-local-server group good pool p1 address-range low 10.0.61.100 high 10.0.61.199",
		"set system services dhcp-local-server group bad interface reth1.7",
		"set system services dhcp-local-server group bad pool p1 subnet 10.0.99.0/24",
		"set interfaces reth1 unit 80 vlan-id 180 family inet address 10.0.180.1/24",
		"set system services dhcp-local-server group bad pool p1 address-range low 10.0.99.100 high 10.0.99.199",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestDesiredStandaloneDropsPhantom15206(t *testing.T) {
	cfg := phantomCfg15206(t)
	out := desiredStandaloneDHCPConfig(cfg)
	good := out.DHCPLocalServer.Groups["good"]
	if good == nil || len(good.Interfaces) != 1 || good.Interfaces[0] != "ge-0-0-2" {
		t.Fatalf("good group must resolve to its real member device, got %+v", good)
	}
	bad := out.DHCPLocalServer.Groups["bad"]
	if bad == nil {
		t.Fatal("bad group must survive with an empty interface list (renderer skips its subnets)")
	}
	for _, iface := range bad.Interfaces {
		if strings.Contains(iface, "reth1.7") {
			t.Fatalf("phantom survived the belt: %v", bad.Interfaces)
		}
	}
	if len(bad.Interfaces) != 0 {
		t.Fatalf("phantom-only group must have no interfaces left, got %v", bad.Interfaces)
	}
	// #9141: the shared active config keeps the authored refs.
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["bad"].Interfaces; len(got) != 1 || got[0] != "reth1.7" {
		t.Fatalf("shared active config mutated: bad interfaces = %v", got)
	}
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["good"].Interfaces; len(got) != 1 || got[0] != "reth1.0" {
		t.Fatalf("shared active config mutated: good interfaces = %v", got)
	}
}
