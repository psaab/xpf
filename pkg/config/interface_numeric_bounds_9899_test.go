package config

import (
	"strings"
	"testing"
)

// #9899 F030/F031: canonical unsigned numeric parsing plus bounds for
// interface tunnel and VLAN leaves.
//
// Bounds: key 0..4294967295, TTL 1..255 (omitted TTL stays 0 = default 64),
// VLAN/inner 0..4094. Canonical form is unsigned decimal digits only: signs
// and whitespace reject. VLAN0 is the untagged sentinel and stays accepted;
// explicit TTL0 now rejects. QinQ strict gate is unchanged: any inner
// presence still refuses strict, lenient range-valid 0 survives and
// range-invalid 4095 skips the unit.
//
// Compiler contract (direct Compile entry; strict Schema already rejects some
// old values but lenient still wraps, so these tests drive CompileConfig and
// CompileConfigLenient, never a schema-first path):
//   - strict: malformed numeric is a hard error naming iface + leaf + raw.
//   - lenient: path+raw-token warning AND quarantine: malformed interface
//     tunnel quarantines the whole owning interface (absent, or Tunnel nil
//     with no emitted endpoint); malformed unit tunnel/VLAN skips only the
//     owning unit. No keyed->unkeyed zeroing, no inherited-tunnel fallback,
//     no tagged->untagged fallback to VlanID 0. Valid siblings remain.
//
// Coverage is distributed, not a cross product: each failure mode (negative,
// u32 overflow, TTL0/256, sign, leading/trailing whitespace, garbage)
// appears once per suite, spread across iface/unit sites and flat/hier
// spellings so both sites and both spellings are exercised.
//
// FAIL-ON-REVERT: restoring bare Atoi with discarded errors and uint32 casts
// flips every RED row below back to green-accept (wrap or fallback to the
// zero sentinel) with no warning and the quarantine/emission assertions fail.

func ifaceNumFlatTree9899(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func ifaceNumHierTree9899(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("hierarchical fixture must parse: %v", errs)
	}
	return tree
}

func ifaceNumWarnHas9899(warnings []string, subs ...string) bool {
	for _, w := range warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func ifaceNumEmitted9899(cfg *Config) map[string]*TunnelConfig {
	m := make(map[string]*TunnelConfig)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		m[ep.Name] = ep.Tunnel
	}
	return m
}

func ifaceNumStrictMustContain9899(t *testing.T, tree *ConfigTree, what string, subs ...string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict CompileConfig ACCEPTED %s; want rejection (#9899)", what)
	}
	for _, s := range subs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("strict error for %s must name %q; got: %v", what, s, err)
		}
	}
}

func ifaceNumLenientMustWarn9899(t *testing.T, tree *ConfigTree, what string, subs ...string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT reject %s (no-brick #1960); got: %v", what, err)
	}
	if cfg == nil {
		t.Fatal("lenient compile returned nil config")
	}
	if !ifaceNumWarnHas9899(cfg.Warnings, subs...) {
		t.Errorf("lenient warnings for %s must name %v; got: %v", what, subs, cfg.Warnings)
	}
	return cfg
}

func ifaceNumSchemaFlat9899(t *testing.T, cmds ...string) error {
	t.Helper()
	return SchemaValidate(ifaceNumFlatTree9899(t, cmds...), nil)
}

func ifaceNumSchemaHier9899(t *testing.T, text string) error {
	t.Helper()
	return SchemaValidate(ifaceNumHierTree9899(t, text), nil)
}

func ifaceNumAssertSchema9899(t *testing.T, what, leaf string, err error, accept bool) {
	t.Helper()
	if accept && err != nil {
		t.Errorf("schema must ACCEPT %s: %v", what, err)
	}
	if !accept {
		if err == nil {
			t.Errorf("schema must REJECT %s (got nil)", what)
			return
		}
		if !strings.Contains(err.Error(), leaf) {
			t.Errorf("schema reject %s must reference %q: %v", what, leaf, err)
		}
	}
}

// TestInterfaceTunnelBounds9899 is the compiler gate for tunnel key/TTL.
func TestInterfaceTunnelBounds9899(t *testing.T) {
	red := []struct {
		name      string
		isUnit    bool
		iface     string
		unit      int
		leaf      string
		raw       string
		checkRaw  bool
		flat      []string
		hier      string
		sibKey    int
		sibTTL    int
		sibHasTun bool
	}{
		{
			name: "iface key negative flat", iface: "gr-0/0/0",
			leaf: "key", raw: "-1", checkRaw: true,
			flat: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 tunnel key -1",
				"set interfaces gr-0/0/1 tunnel source 10.0.1.1",
				"set interfaces gr-0/0/1 tunnel destination 10.0.1.2",
				"set interfaces gr-0/0/1 tunnel key 100",
			},
			sibKey: 100, sibHasTun: true,
		},
		{
			name: "unit key u32 overflow flat", isUnit: true,
			iface: "gr-0/0/0", unit: 5, leaf: "key", raw: "4294967296", checkRaw: true,
			flat: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 tunnel key 100",
				"set interfaces gr-0/0/0 unit 5 tunnel source 10.0.5.1",
				"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.5.2",
				"set interfaces gr-0/0/0 unit 5 tunnel key 4294967296",
				"set interfaces gr-0/0/0 unit 6 family inet address 10.0.6.1/24",
			},
			sibKey: 100,
		},
		{
			name: "iface ttl explicit zero hier", iface: "gr-0/0/0",
			leaf: "ttl", raw: "0", checkRaw: false,
			hier: `interfaces {
  gr-0/0/0 {
    tunnel {
      source 10.0.0.1;
      destination 10.0.0.2;
      ttl 0;
    }
  }
  gr-0/0/1 {
    tunnel {
      source 10.0.1.1;
      destination 10.0.1.2;
      ttl 64;
    }
  }
}`,
			sibTTL: 64, sibHasTun: true,
		},
		{
			name: "unit ttl 256 hier", isUnit: true,
			iface: "gr-0/0/0", unit: 5, leaf: "ttl", raw: "256", checkRaw: true,
			hier: `interfaces {
  gr-0/0/0 {
    tunnel {
      source 10.0.0.1;
      destination 10.0.0.2;
    }
    unit 5 {
      tunnel {
        source 10.0.5.1;
        destination 10.0.5.2;
        ttl 256;
      }
    }
    unit 6 {
      family inet {
        address 10.0.6.1/24;
      }
    }
  }
}`,
		},
		{
			name: "iface key plus sign hier", iface: "gr-0/0/0",
			leaf: "key", raw: "+1", checkRaw: true,
			hier: `interfaces {
  gr-0/0/0 {
    tunnel {
      source 10.0.0.1;
      destination 10.0.0.2;
      key +1;
    }
  }
  gr-0/0/1 {
    tunnel {
      source 10.0.1.1;
      destination 10.0.1.2;
      key 1;
    }
  }
}`,
			sibKey: 1, sibHasTun: true,
		},
		{
			name: "unit ttl leading space flat", isUnit: true,
			iface: "gr-0/0/0", unit: 5, leaf: "ttl", raw: " 64", checkRaw: true,
			flat: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 unit 5 tunnel source 10.0.5.1",
				"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.5.2",
				`set interfaces gr-0/0/0 unit 5 tunnel ttl " 64"`,
				"set interfaces gr-0/0/0 unit 6 family inet address 10.0.6.1/24",
			},
		},
		{
			name: "iface ttl garbage flat", iface: "gr-0/0/0",
			leaf: "ttl", raw: "abc", checkRaw: true,
			flat: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 tunnel ttl abc",
				"set interfaces gr-0/0/1 tunnel source 10.0.1.1",
				"set interfaces gr-0/0/1 tunnel destination 10.0.1.2",
				"set interfaces gr-0/0/1 tunnel ttl 64",
			},
			sibTTL: 64, sibHasTun: true,
		},
		{
			name: "unit key trailing space hier", isUnit: true,
			iface: "gr-0/0/0", unit: 5, leaf: "key", raw: "1 ", checkRaw: true,
			hier: `interfaces {
  gr-0/0/0 {
    tunnel {
      source 10.0.0.1;
      destination 10.0.0.2;
      key 100;
    }
    unit 5 {
      tunnel {
        source 10.0.5.1;
        destination 10.0.5.2;
        key "1 ";
      }
    }
    unit 6 {
      family inet {
        address 10.0.6.1/24;
      }
    }
  }
}`,
			sibKey: 100,
		},
	}

	for _, tc := range red {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.hier != "" {
				tree = ifaceNumHierTree9899(t, tc.hier)
			} else {
				tree = ifaceNumFlatTree9899(t, tc.flat...)
			}
			want := []string{tc.iface, tc.leaf}
			if tc.checkRaw {
				want = append(want, tc.raw)
			}
			what := "malformed " + tc.leaf + " " + tc.raw + " on " + tc.iface
			ifaceNumStrictMustContain9899(t, tree, what, want...)

			var ltree *ConfigTree
			if tc.hier != "" {
				ltree = ifaceNumHierTree9899(t, tc.hier)
			} else {
				ltree = ifaceNumFlatTree9899(t, tc.flat...)
			}
			cfg := ifaceNumLenientMustWarn9899(t, ltree, what, want...)
			eps := ifaceNumEmitted9899(cfg)
			if !tc.isUnit {
				// Quarantine admits absent or Tunnel-nil; either way no
				// keyed->unkeyed survival and no emitted endpoint.
				if got := cfg.Interfaces.Interfaces[tc.iface]; got != nil && got.Tunnel != nil {
					t.Errorf("lenient must QUARANTINE interface %q (%s); got surviving tunnel %+v", tc.iface, what, got.Tunnel)
				}
				if _, ok := eps[tc.iface]; ok {
					t.Errorf("quarantined interface %q must emit no endpoint; got %v", tc.iface, eps)
				}
				sib := cfg.Interfaces.Interfaces["gr-0/0/1"]
				if sib == nil || sib.Tunnel == nil {
					t.Fatalf("valid sibling gr-0/0/1 must survive; got %+v", sib)
				}
				if tc.sibHasTun && tc.leaf == "key" && sib.Tunnel.Key != uint32(tc.sibKey) {
					t.Errorf("sibling key = %d, want %d", sib.Tunnel.Key, tc.sibKey)
				}
				if tc.sibHasTun && tc.leaf == "ttl" && sib.Tunnel.TTL != tc.sibTTL {
					t.Errorf("sibling ttl = %d, want %d", sib.Tunnel.TTL, tc.sibTTL)
				}
				if _, ok := eps["gr-0/0/1"]; !ok {
					t.Errorf("valid sibling gr-0/0/1 must still emit; got %v", eps)
				}
				return
			}
			ifc := cfg.Interfaces.Interfaces[tc.iface]
			if ifc == nil {
				t.Fatalf("parent %q must survive a unit quarantine; got nil", tc.iface)
			}
			if got := ifc.Units[tc.unit]; got != nil {
				t.Errorf("lenient must SKIP unit %d (%s); got %+v — inherited-tunnel fallback", tc.unit, what, got.Tunnel)
			}
			if _, ok := eps[tc.iface+".5"]; ok {
				t.Errorf("quarantined unit %s.5 must emit no endpoint; got %v", tc.iface, eps)
			}
			sib := ifc.Units[6]
			if sib == nil {
				t.Fatalf("valid sibling unit 6 must survive")
			}
			if _, ok := eps[tc.iface+".6"]; !ok {
				t.Errorf("sibling unit %s.6 must still emit via parent; got %v", tc.iface, eps)
			}
			if sib.Tunnel != nil {
				t.Errorf("sibling unit 6 must inherit (Tunnel nil); got %+v", sib.Tunnel)
			}
		})
	}

	t.Run("valid key zero plus omitted ttl flat", func(t *testing.T) {
		cmds := []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 tunnel key 0",
		}
		cfg, err := CompileConfig(ifaceNumFlatTree9899(t, cmds...))
		if err != nil {
			t.Fatalf("valid key 0 + omitted TTL must compile: %v", err)
		}
		tun := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
		if tun == nil || tun.Key != 0 || tun.TTL != 0 {
			t.Fatalf("key 0 + omitted TTL must compile as 0/0; got %+v", tun)
		}
		if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/0"]; !ok {
			t.Fatalf("valid tunnel with omitted TTL must still emit")
		}
		lcfg, err := CompileConfigLenient(ifaceNumFlatTree9899(t, cmds...))
		if err != nil {
			t.Fatalf("lenient valid control: %v", err)
		}
		if ifaceNumWarnHas9899(lcfg.Warnings, "key") || ifaceNumWarnHas9899(lcfg.Warnings, "ttl") {
			t.Errorf("valid key 0 + omitted TTL must not warn; got %v", lcfg.Warnings)
		}
	})

	t.Run("valid unit key max plus ttl max hier", func(t *testing.T) {
		cfg, err := CompileConfig(ifaceNumHierTree9899(t, `interfaces {
  gr-0/0/0 {
    tunnel {
      source 10.0.0.1;
      destination 10.0.0.2;
    }
    unit 5 {
      tunnel {
        source 10.0.5.1;
        destination 10.0.5.2;
        key 4294967295;
        ttl 255;
      }
    }
    unit 6 {
      family inet {
        address 10.0.6.1/24;
      }
    }
  }
}`))
		if err != nil {
			t.Fatalf("valid key max + TTL 255 must compile: %v", err)
		}
		u5 := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[5]
		if u5 == nil || u5.Tunnel == nil || u5.Tunnel.Key != 4294967295 || u5.Tunnel.TTL != 255 {
			t.Fatalf("boundaries must compile as written; got %+v", u5)
		}
		eps := ifaceNumEmitted9899(cfg)
		if _, ok := eps["gr-0/0/0.5"]; !ok {
			t.Errorf("valid unit tunnel must emit gr-0/0/0.5")
		}
		if _, ok := eps["gr-0/0/0.6"]; !ok {
			t.Errorf("inheriting sibling must emit gr-0/0/0.6")
		}
	})

	t.Run("valid ttl one flat", func(t *testing.T) {
		cfg, err := CompileConfig(ifaceNumFlatTree9899(t,
			"set interfaces gr-0/0/1 tunnel source 10.0.1.1",
			"set interfaces gr-0/0/1 tunnel destination 10.0.1.2",
			"set interfaces gr-0/0/1 tunnel key 1",
			"set interfaces gr-0/0/1 tunnel ttl 1",
		))
		if err != nil {
			t.Fatalf("valid TTL 1 must compile: %v", err)
		}
		tun := cfg.Interfaces.Interfaces["gr-0/0/1"].Tunnel
		if tun == nil || tun.TTL != 1 || tun.Key != 1 {
			t.Fatalf("TTL 1 + key 1 must compile as written; got %+v", tun)
		}
	})
}

// TestInterfaceVLANBounds9899 is the compiler gate for vlan-id/inner-vlan-id.
func TestInterfaceVLANBounds9899(t *testing.T) {
	// Outer rows are strict+lenient RED; inner rows are lenient-quarantine
	// RED only (strict already refuses via the unchanged QinQ gate).
	red := []struct {
		name    string
		leaf    string
		raw     string
		isInner bool
		flat    []string
		hier    string
	}{
		{
			name: "outer 4095 flat", leaf: "vlan-id", raw: "4095",
			flat: []string{
				"set interfaces ge-0/0/2 unit 50 vlan-id 4095",
				"set interfaces ge-0/0/2 unit 51 vlan-id 10",
			},
		},
		{
			name: "outer negative hier", leaf: "vlan-id", raw: "-1",
			hier: `interfaces {
  ge-0/0/2 {
    unit 50 {
      vlan-id -1;
    }
    unit 51 {
      vlan-id 10;
    }
  }
}`,
		},
		{
			// +11 (not +10): on base +10 folds to the sibling's 10 and the
			// failure reads as a collision, not a canonical-form failure.
			name: "outer plus sign flat", leaf: "vlan-id", raw: "+11",
			flat: []string{
				"set interfaces ge-0/0/2 unit 50 vlan-id +11",
				"set interfaces ge-0/0/2 unit 51 vlan-id 10",
			},
		},
		{
			name: "outer trailing space hier", leaf: "vlan-id", raw: "10 ",
			hier: `interfaces {
  ge-0/0/2 {
    unit 50 {
      vlan-id "10 ";
    }
    unit 51 {
      vlan-id 10;
    }
  }
}`,
		},
		{
			name: "outer garbage flat", leaf: "vlan-id", raw: "abc",
			flat: []string{
				"set interfaces ge-0/0/2 unit 50 vlan-id abc",
				"set interfaces ge-0/0/2 unit 51 vlan-id 10",
			},
		},
		{
			name: "inner 4095 flat", leaf: "inner-vlan-id", raw: "4095", isInner: true,
			flat: []string{
				"set interfaces ge-0/0/2 unit 50 vlan-id 10",
				"set interfaces ge-0/0/2 unit 50 inner-vlan-id 4095",
				"set interfaces ge-0/0/2 unit 51 vlan-id 10",
			},
		},
		{
			name: "inner plus sign hier", leaf: "inner-vlan-id", raw: "+100", isInner: true,
			hier: `interfaces {
  ge-0/0/2 {
    unit 50 {
      vlan-id 10;
      inner-vlan-id +100;
    }
    unit 51 {
      vlan-id 10;
    }
  }
}`,
		},
	}

	for _, tc := range red {
		t.Run(tc.name, func(t *testing.T) {
			build := func() *ConfigTree {
				if tc.hier != "" {
					return ifaceNumHierTree9899(t, tc.hier)
				}
				return ifaceNumFlatTree9899(t, tc.flat...)
			}
			what := "malformed " + tc.leaf + " " + tc.raw
			if tc.isInner {
				ifaceNumStrictMustContain9899(t, build(), what, "ge-0/0/2", "inner", tc.raw)
				cfg := ifaceNumLenientMustWarn9899(t, build(), what, "ge-0/0/2", "inner", tc.raw)
				ifc := cfg.Interfaces.Interfaces["ge-0/0/2"]
				if ifc == nil {
					t.Fatalf("parent must survive a unit quarantine; got nil")
				}
				if got := ifc.Units[50]; got != nil {
					t.Errorf("lenient must SKIP unit 50 (%s); got VlanID=%d Inner=%d", what, got.VlanID, got.InnerVlanID)
				}
				if sib := ifc.Units[51]; sib == nil || sib.VlanID != 10 {
					t.Errorf("sibling unit 51 (vlan 10) must survive; got %+v", sib)
				}
				return
			}
			ifaceNumStrictMustContain9899(t, build(), what, "ge-0/0/2", tc.leaf, tc.raw)
			cfg := ifaceNumLenientMustWarn9899(t, build(), what, "ge-0/0/2", tc.leaf, tc.raw)
			ifc := cfg.Interfaces.Interfaces["ge-0/0/2"]
			if ifc == nil {
				t.Fatalf("parent must survive a unit quarantine; got nil")
			}
			if got := ifc.Units[50]; got != nil {
				t.Errorf("lenient must SKIP unit 50 (%s); got VlanID=%d — tagged->untagged fallback", what, got.VlanID)
			}
			if sib := ifc.Units[51]; sib == nil || sib.VlanID != 10 {
				t.Errorf("sibling unit 51 (vlan 10) must survive; got %+v", sib)
			}
		})
	}

	t.Run("valid vlan zero untagged flat", func(t *testing.T) {
		cfg, err := CompileConfig(ifaceNumFlatTree9899(t, "set interfaces ge-0/0/2 unit 50 vlan-id 0"))
		if err != nil {
			t.Fatalf("VLAN 0 must compile: %v", err)
		}
		if u := cfg.Interfaces.Interfaces["ge-0/0/2"].Units[50]; u == nil || u.VlanID != 0 {
			t.Fatalf("VLAN 0 must compile as 0; got %+v", u)
		}
	})

	t.Run("valid vlan boundaries hier", func(t *testing.T) {
		cfg, err := CompileConfig(ifaceNumHierTree9899(t, `interfaces {
  ge-0/0/2 {
    unit 50 {
      vlan-id 1;
    }
    unit 51 {
      vlan-id 4094;
    }
  }
}`))
		if err != nil {
			t.Fatalf("VLAN 1/4094 must compile: %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["ge-0/0/2"]
		if ifc.Units[50] == nil || ifc.Units[50].VlanID != 1 {
			t.Errorf("VLAN 1 must compile as written; got %+v", ifc.Units[50])
		}
		if ifc.Units[51] == nil || ifc.Units[51].VlanID != 4094 {
			t.Errorf("VLAN 4094 must compile as written; got %+v", ifc.Units[51])
		}
	})

	t.Run("valid omitted vlan flat", func(t *testing.T) {
		cfg, err := CompileConfig(ifaceNumFlatTree9899(t,
			"set interfaces ge-0/0/2 unit 50 family inet address 10.0.50.1/24",
		))
		if err != nil {
			t.Fatalf("omitted vlan-id must compile: %v", err)
		}
		if u := cfg.Interfaces.Interfaces["ge-0/0/2"].Units[50]; u == nil || u.VlanID != 0 {
			t.Fatalf("omitted vlan-id is VlanID 0; got %+v", u)
		}
	})

	t.Run("qinq inner zero strict refuses lenient survives", func(t *testing.T) {
		cmds := []string{
			"set interfaces ge-0/0/2 unit 50 vlan-id 10",
			"set interfaces ge-0/0/2 unit 50 inner-vlan-id 0",
		}
		ifaceNumStrictMustContain9899(t, ifaceNumFlatTree9899(t, cmds...), "inner presence", "inner")
		cfg := ifaceNumLenientMustWarn9899(t, ifaceNumFlatTree9899(t, cmds...), "inner presence", "inner")
		u := cfg.Interfaces.Interfaces["ge-0/0/2"].Units[50]
		if u == nil {
			t.Fatalf("lenient must KEEP range-valid inner 0")
		}
		if u.InnerVlanID != 0 || u.VlanID != 10 {
			t.Errorf("inner 0 unit must keep VlanID 10 + Inner 0; got %+v", u)
		}
	})
}

// TestInterfaceTunnelSchemaBounds9899 pins the schema half of the tunnel
// contract: key 0..u32max, TTL 1..255, canonical digits only.
func TestInterfaceTunnelSchemaBounds9899(t *testing.T) {
	flat := []struct {
		template string
		leaf     string
		raw      string
		accept   bool
	}{
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "0", true},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "100", true},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "4294967295", true},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "-1", false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "4294967296", false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "+1", false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", `" 1"`, false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", `"1 "`, false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "abc", false},
		{"set interfaces gr-0/0/0 tunnel key %s", "key", "", false},
		{"set interfaces gr-0/0/0 unit 0 tunnel key %s", "key", "0", true},
		{"set interfaces gr-0/0/0 unit 0 tunnel key %s", "key", "4294967296", false},
		{"set interfaces gr-0/0/0 unit 0 tunnel key %s", "key", "+1", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "1", true},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "64", true},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "255", true},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "0", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "256", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "-1", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "+64", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", `" 64"`, false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "abc", false},
		{"set interfaces gr-0/0/0 tunnel ttl %s", "ttl", "", false},
		{"set interfaces gr-0/0/0 unit 0 tunnel ttl %s", "ttl", "1", true},
		{"set interfaces gr-0/0/0 unit 0 tunnel ttl %s", "ttl", "0", false},
	}
	for _, tc := range flat {
		cmd := strings.TrimSpace(strings.Replace(tc.template, "%s", tc.raw, 1))
		ifaceNumAssertSchema9899(t, cmd, tc.leaf, ifaceNumSchemaFlat9899(t, cmd), tc.accept)
	}

	hier := []struct {
		name   string
		leaf   string
		text   string
		accept bool
	}{
		{"hier ttl zero rejects", "ttl", "interfaces { gr-0/0/0 { tunnel { ttl 0; } } }", false},
		{"hier key plus rejects", "key", "interfaces { gr-0/0/0 { tunnel { key +1; } } }", false},
		{"hier key zero accepts", "key", "interfaces { gr-0/0/0 { tunnel { key 0; } } }", true},
		{"hier ttl max accepts", "ttl", "interfaces { gr-0/0/0 { tunnel { ttl 255; } } }", true},
	}
	for _, tc := range hier {
		ifaceNumAssertSchema9899(t, tc.name, tc.leaf, ifaceNumSchemaHier9899(t, tc.text), tc.accept)
	}
}

// TestInterfaceVLANSchemaBounds9899 pins the schema half of the VLAN contract:
// VLAN/inner 0..4094, canonical digits only.
func TestInterfaceVLANSchemaBounds9899(t *testing.T) {
	flat := []struct {
		template string
		leaf     string
		raw      string
		accept   bool
	}{
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "0", true},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "1", true},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "50", true},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "4094", true},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "4095", false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "-1", false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "+10", false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", `" 10"`, false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", `"10 "`, false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "abc", false},
		{"set interfaces ge-0/0/2 unit 50 vlan-id %s", "vlan-id", "", false},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "0", true},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "100", true},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "4094", true},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "4095", false},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "+100", false},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "abc", false},
		{"set interfaces ge-0/0/2 unit 50 inner-vlan-id %s", "inner-vlan-id", "", false},
	}
	for _, tc := range flat {
		cmd := strings.TrimSpace(strings.Replace(tc.template, "%s", tc.raw, 1))
		ifaceNumAssertSchema9899(t, cmd, tc.leaf, ifaceNumSchemaFlat9899(t, cmd), tc.accept)
	}

	hier := []struct {
		name   string
		leaf   string
		text   string
		accept bool
	}{
		{"hier vlan zero accepts", "vlan-id", "interfaces { ge-0/0/2 { unit 50 { vlan-id 0; } } }", true},
		{"hier inner zero accepts", "inner-vlan-id", "interfaces { ge-0/0/2 { unit 50 { vlan-id 10; inner-vlan-id 0; } } }", true},
		{"hier vlan high rejects", "vlan-id", "interfaces { ge-0/0/2 { unit 50 { vlan-id 4095; } } }", false},
		{"hier inner plus rejects", "inner-vlan-id", "interfaces { ge-0/0/2 { unit 50 { vlan-id 10; inner-vlan-id +100; } } }", false},
	}
	for _, tc := range hier {
		ifaceNumAssertSchema9899(t, tc.name, tc.leaf, ifaceNumSchemaHier9899(t, tc.text), tc.accept)
	}
}

// TestInterfaceNumericEmpty9899 pins explicit-empty/value-less handling: a
// present numeric leaf with no value must reject (strict) / warn+quarantine
// (lenient), while a wholly absent leaf stays valid (omitted TTL/VLAN
// controls above). Three cells catch all guard paths: unit key (inherited
// tunnel, quoted-empty), VLAN (valueless), iface TTL (valueless).
func TestInterfaceNumericEmpty9899(t *testing.T) {
	t.Run("unit key quoted empty no inherit", func(t *testing.T) {
		cmds := []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 tunnel key 100",
			"set interfaces gr-0/0/0 unit 5 tunnel source 10.0.5.1",
			"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.5.2",
			`set interfaces gr-0/0/0 unit 5 tunnel key ""`,
			"set interfaces gr-0/0/0 unit 6 family inet address 10.0.6.1/24",
		}
		what := "explicit empty unit key"
		ifaceNumStrictMustContain9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "key")
		cfg := ifaceNumLenientMustWarn9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "key")
		ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if ifc == nil {
			t.Fatalf("parent must survive a unit quarantine; got nil")
		}
		if got := ifc.Units[5]; got != nil {
			t.Errorf("lenient must SKIP unit 5 (%s); got Key=%d — inherited fallback", what, got.Tunnel.Key)
		}
		if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/0.5"]; ok {
			t.Errorf("quarantined unit gr-0/0/0.5 must emit no endpoint")
		}
		if sib := ifc.Units[6]; sib == nil {
			t.Fatalf("sibling unit 6 must survive")
		}
		if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/0.6"]; !ok {
			t.Errorf("sibling gr-0/0/0.6 must still emit via parent")
		}
	})

	t.Run("vlan valueless no untagged fallback", func(t *testing.T) {
		cmds := []string{
			"set interfaces ge-0/0/2 unit 50 vlan-id",
			"set interfaces ge-0/0/2 unit 51 vlan-id 10",
		}
		what := "valueless vlan-id"
		ifaceNumStrictMustContain9899(t, ifaceNumFlatTree9899(t, cmds...), what, "ge-0/0/2", "vlan-id")
		cfg := ifaceNumLenientMustWarn9899(t, ifaceNumFlatTree9899(t, cmds...), what, "ge-0/0/2", "vlan-id")
		ifc := cfg.Interfaces.Interfaces["ge-0/0/2"]
		if ifc == nil {
			t.Fatalf("parent must survive a unit quarantine; got nil")
		}
		if got := ifc.Units[50]; got != nil {
			t.Errorf("lenient must SKIP unit 50 (%s); got VlanID=%d — tagged->untagged fallback", what, got.VlanID)
		}
		if sib := ifc.Units[51]; sib == nil || sib.VlanID != 10 {
			t.Errorf("sibling unit 51 (vlan 10) must survive; got %+v", sib)
		}
	})

	t.Run("iface ttl valueless quarantines", func(t *testing.T) {
		cmds := []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 tunnel ttl",
			"set interfaces gr-0/0/1 tunnel source 10.0.1.1",
			"set interfaces gr-0/0/1 tunnel destination 10.0.1.2",
			"set interfaces gr-0/0/1 tunnel ttl 64",
		}
		what := "valueless iface ttl"
		ifaceNumStrictMustContain9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "ttl")
		cfg := ifaceNumLenientMustWarn9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "ttl")
		if got := cfg.Interfaces.Interfaces["gr-0/0/0"]; got != nil && got.Tunnel != nil {
			t.Errorf("lenient must QUARANTINE gr-0/0/0 (%s); got %+v", what, got.Tunnel)
		}
		if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/0"]; ok {
			t.Errorf("quarantined gr-0/0/0 must emit no endpoint")
		}
		sib := cfg.Interfaces.Interfaces["gr-0/0/1"]
		if sib == nil || sib.Tunnel == nil || sib.Tunnel.TTL != 64 {
			t.Errorf("sibling gr-0/0/1 (ttl 64) must survive; got %+v", sib)
		}
		if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/1"]; !ok {
			t.Errorf("sibling gr-0/0/1 must still emit")
		}
	})
}

// TestInterfaceFinalUnitQuarantineSuppressesFallback9899 pins P2: when lenient
// compilation quarantines the FINAL unit of an interface that authored units,
// the emitter must NOT fall back to the unitless bare-name endpoint. That
// fallback (tunnelemit.go) is for interfaces authored WITHOUT units; emitting
// it here activates a parent-tunnel endpoint the operator never configured on
// the bare device name. Pre-fix RED: the quarantined interface emits "gr-0/0/0".
func TestInterfaceFinalUnitQuarantineSuppressesFallback9899(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 tunnel ttl 64",
		"set interfaces gr-0/0/0 unit 5 tunnel ttl 256",
	}
	what := "final unit ttl 256"
	ifaceNumStrictMustContain9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "ttl")
	cfg := ifaceNumLenientMustWarn9899(t, ifaceNumFlatTree9899(t, cmds...), what, "gr-0/0/0", "ttl")
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatalf("parent must survive a unit quarantine; got nil")
	}
	if len(ifc.Units) != 0 {
		t.Fatalf("lenient must SKIP the only unit (%s); got %d units", what, len(ifc.Units))
	}
	if _, ok := ifaceNumEmitted9899(cfg)["gr-0/0/0"]; ok {
		t.Errorf("all-units-quarantined must NOT emit the unitless fallback endpoint")
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 0 {
		t.Errorf("quarantined interface must emit no endpoints, got %d", got)
	}
	// Control: a truly unitless interface with the same tunnel still emits.
	unitless := []string{
		"set interfaces gr-0/0/1 tunnel source 10.0.1.1",
		"set interfaces gr-0/0/1 tunnel destination 10.0.1.2",
		"set interfaces gr-0/0/1 tunnel ttl 64",
	}
	cfg2, err := CompileConfigLenient(ifaceNumFlatTree9899(t, unitless...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ifaceNumEmitted9899(cfg2)["gr-0/0/1"]; !ok {
		t.Errorf("truly unitless interface must still emit its bare-name endpoint")
	}
}
