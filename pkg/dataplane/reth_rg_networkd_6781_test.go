package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6781: buildInterfaceNetworkdModels decided "is this a VRRP-backed reth
// member?" and, for an interface with NO `redundant-parent`, answered from a
// bare `RedundancyGroup > 0`. A genuine RG owner never reaches that arm — the
// skip above it keys on RethToPhysical — so the arm only ever fired on the
// broken shape: `redundant-ether-options redundancy-group` on an interface that
// is neither a reth member nor a reth owner.
//
// When it fired it REPLACED the operator's configured address with a
// 169.254.<rg>.<node>/32 link-local and set KeepConfiguration=static, handing
// the real address to VRRP as a virtual address. Under `no-reth-vrrp` the
// direct owner skipped the interface too, so the address was stripped here and
// installed by NOBODY, on both nodes.
//
// FAIL-ON-REVERT: restore `isVRRPReth = ifCfg.RedundancyGroup > 0 &&
// clusterNodeID >= 0` in that else arm and this goes RED — the configured
// address disappears from the model and a 169.254.x/32 takes its place.

func rethRGNetworkdCfg(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6781",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		// Neither a reth member nor a reth owner, but carries a group.
		"set interfaces ge-0/0/5 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.99.1/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Tolerant path: strict commit now rejects this shape, and the point here
	// is what the generator does with a config that reached it anyway.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick (#1960): %v", err)
	}
	return cfg
}

func TestNetworkdKeepsAddressOfNonRethCarryingRedundancyGroup(t *testing.T) {
	cfg := rethRGNetworkdCfg(t)
	// Seed the netdev so the interface reaches the physical-interface path;
	// without it the model may be skipped for an unrelated reason and the test
	// would pass vacuously.
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-5": {
			Index:        77,
			Name:         "ge-0-0-5",
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x05},
		},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	var found bool
	for _, m := range result.ManagedInterfaces {
		if m.Name != "ge-0-0-5" {
			continue
		}
		found = true
		var hasReal, hasLinkLocal bool
		for _, a := range m.Addresses {
			if a == "10.0.99.1/24" {
				hasReal = true
			}
			if strings.HasPrefix(a, "169.254.") {
				hasLinkLocal = true
			}
		}
		if !hasReal {
			t.Errorf("ge-0-0-5 lost its configured address 10.0.99.1/24 from the "+
				"networkd model (addresses=%v). It is neither a reth member nor "+
				"a reth owner, so nothing may substitute a VRRP link-local for "+
				"its address — under no-reth-vrrp nobody installs the real one "+
				"back, on either node", m.Addresses)
		}
		if hasLinkLocal {
			t.Errorf("ge-0-0-5 was given a VRRP reth link-local (addresses=%v); "+
				"it is not a VRRP-backed reth member", m.Addresses)
		}
		if m.KeepAddresses {
			t.Errorf("ge-0-0-5 was marked KeepAddresses (KeepConfiguration=" +
				"static), which is the VRRP-VIP preservation flag; it owns no VIPs")
		}
	}
	if !found {
		t.Fatalf("ge-0-0-5 produced no networkd model at all, so this test "+
			"asserted nothing; models=%d", len(result.ManagedInterfaces))
	}
}
