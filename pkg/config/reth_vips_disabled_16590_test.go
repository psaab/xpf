package config

import (
	"reflect"
	"testing"
)

// #16590 (#14575 residual): RethVIPsForRG must skip ifc.Disable and
// unit.Disable so install, GARP, readiness and probe source all exclude a
// disabled unit's address. Acceptance: disable-unit80=true arm is ready
// with ge-0-0-2.80 absent; untagged disabled arms give an empty map; the
// enabled control is unchanged.

func rethCfg16590(mutate func(*Config)) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, VlanTagging: true,
			Units: map[int]*InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
				80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

func TestRethVIPsDisabledTaggedUnit16590(t *testing.T) {
	cfg := rethCfg16590(func(c *Config) {
		c.Interfaces.Interfaces["reth0"].Units[80].Disable = true
	})
	got := cfg.RethVIPsForRG(1)
	if _, ok := got["ge-0-0-2.80"]; ok {
		t.Fatalf("disabled unit 80 must be absent, got %v", got)
	}
	if v := got["ge-0-0-2.50"]; !reflect.DeepEqual(v, []string{"172.16.50.8/24"}) {
		t.Fatalf("enabled unit 50 must be unchanged, got %v", got)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 entry, got %v", got)
	}
}

func TestRethVIPsEnabledControl16590(t *testing.T) {
	got := rethCfg16590(nil).RethVIPsForRG(1)
	want := map[string][]string{
		"ge-0-0-2.50": {"172.16.50.8/24"},
		"ge-0-0-2.80": {"172.16.80.8/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enabled control changed: got %v want %v", got, want)
	}
}

func TestRethVIPsDisabledInterface16590(t *testing.T) {
	cfg := rethCfg16590(func(c *Config) {
		c.Interfaces.Interfaces["reth0"].Disable = true
	})
	if got := cfg.RethVIPsForRG(1); len(got) != 0 {
		t.Fatalf("disabled interface must give empty map, got %v", got)
	}
}

func TestRethVIPsDisabledUntagged16590(t *testing.T) {
	mk := func(disableUnit, disableIfc bool) *Config {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"reth0": {
				Name: "reth0", RedundancyGroup: 1, Disable: disableIfc,
				Units: map[int]*InterfaceUnit{
					0: {Number: 0, Disable: disableUnit, Addresses: []string{"10.0.1.1/24"}},
				},
			},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		}
		return cfg
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
		want int
	}{
		{"enabled control", mk(false, false), 1},
		{"unit disabled", mk(true, false), 0},
		{"interface disabled", mk(false, true), 0},
		{"both disabled", mk(true, true), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.RethVIPsForRG(1)
			if len(got) != tc.want {
				t.Fatalf("got %v want %d entries", got, tc.want)
			}
			if tc.want == 1 {
				if v := got["ge-0-0-0"]; !reflect.DeepEqual(v, []string{"10.0.1.1/24"}) {
					t.Fatalf("control VIP wrong: %v", got)
				}
			}
		})
	}
}

// Mixed untagged: disabled unit excluded, enabled sibling kept.
func TestRethVIPsDisabledUntaggedSibling16590(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1,
			Units: map[int]*InterfaceUnit{
				0: {Number: 0, Disable: true, Addresses: []string{"10.0.1.1/24"}},
				1: {Number: 1, Addresses: []string{"10.0.2.1/24"}},
			},
		},
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
	}
	got := cfg.RethVIPsForRG(1)
	if v := got["ge-0-0-0"]; !reflect.DeepEqual(v, []string{"10.0.2.1/24"}) {
		t.Fatalf("only enabled sibling must remain, got %v", got)
	}
}
