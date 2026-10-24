package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #12533 daemon wiring: buildRAConfigs stamps Pinned provenance and the
// per-interface pin set; buildDHCPClientSpecs carries pins into options.

func TestBuildRAConfigsStampsPin12533(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SetDHCPv6Options("ge-0/0/3", &dhcp.DHCPv6Options{IATypes: []string{"ia-pd"}, RAIface: "lan0", PinnedPrefixes: []string{"fd00:1234::/48"}})
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "lan0", []dhcp.DelegatedPrefix{{
		Interface: "ge-0/0/3", Prefix: netip.MustParsePrefix("fd00:1234::/56"),
		PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour, Obtained: time.Now(), Pinned: true,
	}})
	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(&config.Config{})
	found := false
	for _, ra := range ras {
		for _, p := range ra.Prefixes {
			if p.Delegated {
				found = true
				if !p.Pinned {
					t.Fatalf("delegated prefix Pinned=false, want true: %+v", p)
				}
			}
		}
		if len(ra.PinnedPrefixes) != 1 || ra.PinnedPrefixes[0] != "fd00:1234::/48" {
			t.Fatalf("RA PinnedPrefixes=%v want [fd00:1234::/48]", ra.PinnedPrefixes)
		}
	}
	if !found {
		t.Fatal("no delegated prefix in RA configs")
	}
	// Unpinned delegation: Pinned false, no pin set.
	mgr2 := dhcp.NewManagerForTesting(nil)
	mgr2.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "lan0", []dhcp.DelegatedPrefix{{
		Interface: "ge-0/0/3", Prefix: netip.MustParsePrefix("2606:4700:1::/56"),
		PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour, Obtained: time.Now(),
	}})
	d2 := &Daemon{dhcp: mgr2}
	for _, ra := range d2.buildRAConfigs(&config.Config{}) {
		if len(ra.PinnedPrefixes) != 0 {
			t.Fatalf("unpinned RA PinnedPrefixes=%v want empty", ra.PinnedPrefixes)
		}
		for _, p := range ra.Prefixes {
			if p.Pinned {
				t.Fatal("unpinned delegation marked Pinned")
			}
		}
	}
}

func TestBuildDHCPClientSpecsPins12533(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{PinnedPrefixes: []string{"fd00:1234::/48"}}},
		}},
	}
	specs := buildDHCPClientSpecs(cfg)
	if len(specs) != 1 || specs[0].V6 == nil || len(specs[0].V6.PinnedPrefixes) != 1 {
		t.Fatalf("specs=%+v want 1 with pin", specs)
	}
}
