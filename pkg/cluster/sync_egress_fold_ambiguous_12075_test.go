package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func compileIfaceCfgAmbiguous12075(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func ambiguousIfaceCfg12075(t *testing.T) *config.Config {
	t.Helper()
	return compileIfaceCfgAmbiguous12075(t,
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces ge-0-0-1 gigether-options redundant-parent reth1",
	)
}

func unambiguousIfaceCfg12075(t *testing.T) *config.Config {
	t.Helper()
	return compileIfaceCfgAmbiguous12075(t,
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
	)
}

func foldResolver12075(cfg *config.Config) func(uint32, uint16) uint32 {
	return func(_ uint32, vlan uint16) uint32 {
		return config.StableIfaceID(cfg.ClusterStableIfaceName("ge-0-0-1", vlan))
	}
}

func TestStampEgressIfaceFoldAmbiguousReturnsUnknown_12075(t *testing.T) {
	cfg := ambiguousIfaceCfg12075(t)
	var ss SessionSync
	ss.SetIngressFoldFn(foldResolver12075(cfg))

	const n = 10000
	seen := make(map[uint32]int)
	for i := 0; i < n; i++ {
		seen[ss.stampEgressIfaceFold(7, 0)]++
	}
	if len(seen) != 1 || seen[0] != n {
		t.Fatalf("ambiguous egress stamp produced folds %v over %d calls, want exactly {%#x:%d}",
			seen, n, uint32(0), n)
	}
}

func TestStampEgressIfaceFoldUnambiguousDeterministic_12075(t *testing.T) {
	cfg := unambiguousIfaceCfg12075(t)
	var ss SessionSync
	ss.SetIngressFoldFn(foldResolver12075(cfg))

	const n = 10000
	seen := make(map[uint32]int)
	for i := 0; i < n; i++ {
		seen[ss.stampEgressIfaceFold(7, 0)]++
	}
	if len(seen) != 1 {
		t.Fatalf("unambiguous egress stamp produced %d distinct folds %v, want exactly one", len(seen), seen)
	}
	if seen[config.StableIfaceID("reth1")] != n {
		t.Fatalf("unambiguous egress stamp produced folds %v, want reth1 fold %#x on every call",
			seen, config.StableIfaceID("reth1"))
	}
}

func TestAmbiguousZeroFoldUsesZoneApproximation_12075(t *testing.T) {
	cfg := ambiguousIfaceCfg12075(t)
	foldFn := foldResolver12075(cfg)
	if got := foldFn(7, 0); got != 0 {
		t.Fatalf("ambiguous ingress resolver returned %#x, want unknown fold 0", got)
	}

	const zone uint16 = 42
	ss := NewSessionSync(":0", "10.0.0.1:4785", nil)
	ss.IsPrimaryForRGFn = func(rg int) bool { return rg == 1 }
	ss.IsPrimaryFn = func() bool { return false }
	ss.SetZoneOwnership(ZoneRGMap{zone: {1}}, map[uint32]int{
		config.StableIfaceID("reth0"): 2,
		config.StableIfaceID("reth1"): 3,
	}, foldFn)
	val := dataplane.SessionValue{IngressIfindex: 7, IngressZone: zone}
	if !ss.ShouldSyncSessionV4(val) {
		t.Fatal("zero fold did not fall back to the zone's primary RG")
	}
}
