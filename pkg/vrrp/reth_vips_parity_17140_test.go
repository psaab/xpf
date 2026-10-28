package vrrp

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17140: one RETH VIP walk. CollectRethInstances must equal RethVIPsForRG
// entry-for-entry (interface -> VirtualAddresses, in order) for every
// fixture, including alias spellings that canonical-dedupe (#11482) and
// disabled units/interfaces (#16590) that are skipped once in the shared
// walk. On pre-fix master the direct map carried the alias twice while
// the VRRP instance carried it once, so the alias cells fail there.

func rethCfg17140(tagged bool, addrs50, addrs80 []string, disable80, disableIfc bool) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, Disable: disableIfc, VlanTagging: tagged,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: addrs50},
				80: {Number: 80, VlanID: 80, Disable: disable80, Addresses: addrs80},
			},
		},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
	}
	if !tagged {
		// Untagged: units contribute to the base interface in unit order.
		cfg.Interfaces.Interfaces["reth0"].Units = map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: addrs50},
			1: {Number: 1, Disable: disable80, Addresses: addrs80},
		}
	}
	return cfg
}

func assertParity17140(t *testing.T, cfg *config.Config) {
	t.Helper()
	instMap := map[string][]string{}
	var order []string
	for _, inst := range CollectRethInstances(cfg, map[int]int{1: 200}) {
		if _, dup := instMap[inst.Interface]; dup {
			t.Fatalf("duplicate instance for %q", inst.Interface)
		}
		instMap[inst.Interface] = inst.VirtualAddresses
		order = append(order, inst.Interface)
	}
	direct := RethVIPsForRG(cfg, 1)
	// Normalise empty vs nil: an RG with no VIPs yields nil/empty both sides.
	if len(instMap) == 0 && len(direct) == 0 {
		return
	}
	if !reflect.DeepEqual(instMap, direct) {
		t.Fatalf("parity mismatch:\n vrrp=%v (order %v)\n direct=%v", instMap, order, direct)
	}
	// Pin order: instances sorted by interface name must match sorted keys.
	sorted := append([]string(nil), order...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] < sorted[i-1] {
			t.Fatalf("instance order not pinned sorted: %v", order)
		}
	}
}

func TestRethVIPParityAliasTagged17140(t *testing.T) {
	// Alias spellings of one IPv6 VIP on unit 50; distinct VIP on unit 80.
	cfg := rethCfg17140(true,
		[]string{"2001:db8:61::1/64", "2001:DB8:61:0::1/64"},
		[]string{"10.0.80.1/24"}, false, false)
	assertParity17140(t, cfg)
	got := RethVIPsForRG(cfg, 1)
	if v := got["ge-0-0-1.50"]; !reflect.DeepEqual(v, []string{"2001:db8:61::1/64"}) {
		t.Fatalf("alias must dedupe to one entry, got %v", got)
	}
	if v := got["ge-0-0-1.80"]; !reflect.DeepEqual(v, []string{"10.0.80.1/24"}) {
		t.Fatalf("control unit 80 changed, got %v", got)
	}
}

func TestRethVIPParityAliasUntagged17140(t *testing.T) {
	cfg := rethCfg17140(false,
		[]string{"2001:db8:61::1/64"},
		[]string{"2001:DB8:61:0::1/64"}, false, false)
	assertParity17140(t, cfg)
	got := RethVIPsForRG(cfg, 1)
	if v := got["ge-0-0-1"]; !reflect.DeepEqual(v, []string{"2001:db8:61::1/64"}) {
		t.Fatalf("untagged alias must dedupe to one entry, got %v", got)
	}
}

func TestRethVIPParityDisabled17140(t *testing.T) {
	// Disabled unit 80 excluded in both modes; enabled control kept.
	cfg := rethCfg17140(true,
		[]string{"10.0.50.1/24"}, []string{"10.0.80.1/24"}, true, false)
	assertParity17140(t, cfg)
	if got := RethVIPsForRG(cfg, 1); len(got) != 1 {
		t.Fatalf("disabled unit must leave 1 entry, got %v", got)
	}
	// Disabled interface: empty both sides.
	cfg = rethCfg17140(true,
		[]string{"10.0.50.1/24"}, []string{"10.0.80.1/24"}, false, true)
	assertParity17140(t, cfg)
	if got := RethVIPsForRG(cfg, 1); len(got) != 0 {
		t.Fatalf("disabled interface must give empty map, got %v", got)
	}
	// Enabled control: both entries.
	cfg = rethCfg17140(true,
		[]string{"10.0.50.1/24"}, []string{"10.0.80.1/24"}, false, false)
	assertParity17140(t, cfg)
}

func TestRethVIPParityControl17140(t *testing.T) {
	cfg := rethCfg17140(true,
		[]string{"10.0.50.1/24"}, []string{"10.0.80.1/24"}, false, false)
	assertParity17140(t, cfg)
	want := map[string][]string{
		"ge-0-0-1.50": {"10.0.50.1/24"},
		"ge-0-0-1.80": {"10.0.80.1/24"},
	}
	if got := RethVIPsForRG(cfg, 1); !reflect.DeepEqual(got, want) {
		t.Fatalf("control changed: got %v want %v", got, want)
	}
	// ByRG agrees with ForRG.
	byRG := cfg.RethVIPsByRG()
	if !reflect.DeepEqual(byRG[1], want) {
		t.Fatalf("RethVIPsByRG[1] = %v want %v", byRG[1], want)
	}
}

// Two-RG order pin (#17140 fold): with reth0 in RG 2 and reth1 in RG 1,
// CollectRethInstances must emit RG-major order — RG 1's instance (reth1's
// physical ge-0-0-1) first, then RG 2's (reth0's ge-0-0-0) — NOT name order
// (ge-0-0-0 < ge-0-0-1) and NOT map iteration. Exact sequence assertion so
// replacing the sorted RG loop with bare map iteration reds this cell.
func TestRethInstanceOrderRGMajor17140(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 2,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.20.1/24"}},
			},
		},
		"reth1": {
			Name: "reth1", RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.10.1/24"}},
			},
		},
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
	}
	insts := CollectRethInstances(cfg, map[int]int{1: 200, 2: 100})
	if len(insts) != 2 {
		t.Fatalf("got %d instances, want 2: %+v", len(insts), insts)
	}
	type id struct {
		iface string
		vrid  int
		vips  []string
	}
	got := make([]id, 0, len(insts))
	for _, in := range insts {
		got = append(got, id{in.Interface, in.GroupID, in.VirtualAddresses})
	}
	// RG ascending: RG1 (VRID 101, reth1->ge-0-0-1) before RG2 (VRID 102,
	// reth0->ge-0-0-0), even though ge-0-0-0 sorts before ge-0-0-1.
	want := []id{
		{"ge-0-0-1", 101, []string{"10.0.10.1/24"}},
		{"ge-0-0-0", 102, []string{"10.0.20.1/24"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instance sequence = %+v, want RG-major %+v", got, want)
	}
}
