package config

import (
	"reflect"
	"testing"
)

// #15017 (A12-05): the `protocols rip` and `protocols ospf3` TOP readers
// iterated only the top node's Children, so a hierarchical line that
// packs a leaf tail beside a braced body dropped the tail in silence:
//
//	rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; }
//	    AuthKey="" AuthType="" — RIP runs UNAUTHENTICATED (FRR renders
//	    `ip rip authentication mode text` / no auth) while the braced
//	    neighbor survives, so the commit reports success.
//
//	ospf3 router-id 1.1.1.1 export connected { area 0.0.0.0 { ... } }
//	    RouterID="" Export=[] while the area survives.
//
// The plain packed line with NO braced body was already rescued by
// the #8662 compact normalizer (`rip authentication-key` /
// `rip authentication-type` are in its scope; `ospf3 router-id` folds
// the same way), so it is a CONTROL here, not the defect — the
// reproducer that survives is the mixed tail+braced shape, where
// packedBodyChildren declines (its deepest packed node is a leaf).
// The acceptance oracle from the issue: the packed cases yield
// AuthType "md5" with the 6-rune key "secret", and the braced
// control is unchanged. compileProtocols is shared by
// `routing-instances … protocols`, so both scopes are pinned.
//
// Census: every `protocols <p>` top that carries top-level leaves is
// exercised in the surviving mixed shape below (ospf #14427, isis
// #14426, rip + ospf3 here). BGP/LLDP tops are covered by their
// flat-run/chain readers and have no mixed-shape drop today;
// router-advertisement's top node carries no leaves of its own.

func ripPackedCompile15017(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected fixture %q: %v", text, err)
	}
	if cfg == nil || cfg.Protocols.RIP == nil {
		t.Fatalf("fixture produced no RIP config: %q", text)
	}
	return cfg
}

func checkRIP15017(t *testing.T, label string, cfg *Config, wantKey, wantType string, wantIfaces []string) {
	t.Helper()
	rip := cfg.Protocols.RIP
	if got := rip.AuthKey.Reveal(); got != wantKey {
		t.Errorf("%s: AuthKey = %q, want %q — FRR renders RIP unauthenticated (#15017)", label, got, wantKey)
	}
	if rip.AuthType != wantType {
		t.Errorf("%s: AuthType = %q, want %q (#15017)", label, rip.AuthType, wantType)
	}
	if wantIfaces != nil && !reflect.DeepEqual(rip.Interfaces, wantIfaces) {
		t.Errorf("%s: Interfaces = %v, want %v (#15017)", label, rip.Interfaces, wantIfaces)
	}
}

func TestRIPPackedTopAuth15017(t *testing.T) {
	// Braced positive control: must carry the values, or every packed
	// comparison below passes vacuously against empty fields. The key
	// is the issue's oracle key: 6 runes, type md5.
	t.Run("braced control", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip { authentication-key secret; authentication-type md5; neighbor ge-0/0/0.0; } }")
		checkRIP15017(t, "braced", cfg, "secret", "md5", []string{"ge-0/0/0.0"})
		if n := len([]rune(cfg.Protocols.RIP.AuthKey.Reveal())); n != 6 {
			t.Fatalf("braced control key length = %d, want 6 (issue oracle)", n)
		}
	})

	// The surviving defect shape: packed auth tail beside a braced body.
	t.Run("packed tail with braced neighbor", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; } }")
		checkRIP15017(t, "packed+braced", cfg, "secret", "md5", []string{"ge-0/0/0.0"})
		if n := len([]rune(cfg.Protocols.RIP.AuthKey.Reveal())); n != 6 {
			t.Errorf("packed+braced key length = %d, want 6 (issue oracle)", n)
		}
	})

	// Packed tail ending in a braced authentication-type body: the
	// type must still land beside the key from the tail.
	t.Run("packed key with braced type body", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret { authentication-type md5; } }")
		checkRIP15017(t, "packed key + braced type", cfg, "secret", "md5", nil)
	})

	// Packed tail that ends in the group container: the group content
	// expands as children of the synthesized group node.
	t.Run("packed tail ending in group", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret authentication-type md5 group g1 { neighbor ge-0/0/1.0; } }")
		checkRIP15017(t, "packed group tail", cfg, "secret", "md5", []string{"ge-0/0/1.0"})
	})

	// Packed == braced, field for field, on the trigger spelling.
	t.Run("packed equals braced", func(t *testing.T) {
		packed := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; } }").Protocols.RIP
		braced := ripPackedCompile15017(t,
			"protocols { rip { authentication-key secret; authentication-type md5; neighbor ge-0/0/0.0; } }").Protocols.RIP
		if packed.AuthKey.Reveal() != braced.AuthKey.Reveal() || packed.AuthType != braced.AuthType ||
			!reflect.DeepEqual(packed.Interfaces, braced.Interfaces) {
			t.Errorf("packed (%q/%q %v) != braced (%q/%q %v) (#15017)",
				packed.AuthKey.Reveal(), packed.AuthType, packed.Interfaces,
				braced.AuthKey.Reveal(), braced.AuthType, braced.Interfaces)
		}
	})

	// Controls that already worked and must not move: the plain packed
	// line (folded by the #8662 normalizer) and the nested flat-run
	// spelling inside a braced rip block.
	t.Run("plain packed line control", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret authentication-type md5; }")
		checkRIP15017(t, "plain packed", cfg, "secret", "md5", nil)
	})
	t.Run("nested flat-run control", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip { authentication-key secret authentication-type md5; } }")
		checkRIP15017(t, "nested flat-run", cfg, "secret", "md5", nil)
	})

	// Routing-instance spelling shares compileProtocols and must agree.
	t.Run("routing-instance packed tail with braced neighbor", func(t *testing.T) {
		tree, perrs := NewParser(
			"routing-instances { VRF-A { protocols { rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; } } } }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile rejected routing-instance fixture: %v", err)
		}
		var riRIP *RIPConfig
		for _, ri := range cfg.RoutingInstances {
			if ri != nil && ri.RIP != nil {
				riRIP = ri.RIP
			}
		}
		if riRIP == nil {
			t.Fatalf("routing-instance fixture produced no RIP config: %+v", cfg.RoutingInstances)
		}
		if riRIP.AuthKey.Reveal() != "secret" || riRIP.AuthType != "md5" ||
			!reflect.DeepEqual(riRIP.Interfaces, []string{"ge-0/0/0.0"}) {
			t.Errorf("routing-instance packed: key=%q type=%q ifaces=%v, want secret/md5/[ge-0/0/0.0] (#15017)",
				riRIP.AuthKey.Reveal(), riRIP.AuthType, riRIP.Interfaces)
		}
	})
}

func ospf3PackedCompile15017(t *testing.T, text string) *OSPFv3Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected fixture %q: %v", text, err)
	}
	if cfg == nil || cfg.Protocols.OSPFv3 == nil {
		t.Fatalf("fixture produced no OSPFv3 config: %q", text)
	}
	return cfg.Protocols.OSPFv3
}

func checkOSPF3_15017(t *testing.T, label string, got *OSPFv3Config, wantRID string, wantExport []string, wantAreas int) {
	t.Helper()
	if got.RouterID != wantRID {
		t.Errorf("%s: RouterID = %q, want %q (#15017)", label, got.RouterID, wantRID)
	}
	if wantExport != nil && !reflect.DeepEqual(got.Export, wantExport) {
		t.Errorf("%s: Export = %v, want %v (#15017)", label, got.Export, wantExport)
	}
	if len(got.Areas) != wantAreas {
		t.Errorf("%s: Areas = %d, want %d (#15017)", label, len(got.Areas), wantAreas)
	}
}

func TestOSPF3PackedTop15017(t *testing.T) {
	// Braced positive control.
	t.Run("braced control", func(t *testing.T) {
		got := ospf3PackedCompile15017(t,
			"protocols { ospf3 { router-id 1.1.1.1; export connected; area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		checkOSPF3_15017(t, "braced", got, "1.1.1.1", []string{"connected"}, 1)
		if len(got.Areas) == 1 && (len(got.Areas[0].Interfaces) != 1 || got.Areas[0].Interfaces[0].Name != "ge-0/0/0.0") {
			t.Errorf("braced control interfaces broken: %+v", got.Areas)
		}
	})

	// The surviving defect shape: packed router-id/export tail beside
	// the braced area.
	t.Run("packed tail with braced area", func(t *testing.T) {
		got := ospf3PackedCompile15017(t,
			"protocols { ospf3 router-id 1.1.1.1 export connected { area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		checkOSPF3_15017(t, "packed+braced", got, "1.1.1.1", []string{"connected"}, 1)
		if len(got.Areas) == 1 && (len(got.Areas[0].Interfaces) != 1 || got.Areas[0].Interfaces[0].Name != "ge-0/0/0.0") {
			t.Errorf("packed+braced interfaces broken: %+v", got.Areas)
		}
	})

	// Both packed orders must agree (export is multi; the tail walker
	// must not depend on which leaf comes first).
	t.Run("export first packed tail", func(t *testing.T) {
		got := ospf3PackedCompile15017(t,
			"protocols { ospf3 export connected router-id 1.1.1.1 { area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		checkOSPF3_15017(t, "export-first", got, "1.1.1.1", []string{"connected"}, 1)
	})
	t.Run("router-id only packed tail", func(t *testing.T) {
		got := ospf3PackedCompile15017(t,
			"protocols { ospf3 router-id 2.2.2.2 { area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		checkOSPF3_15017(t, "rid-only", got, "2.2.2.2", nil, 1)
	})

	// Packed == braced, field for field.
	t.Run("packed equals braced", func(t *testing.T) {
		packed := ospf3PackedCompile15017(t,
			"protocols { ospf3 router-id 1.1.1.1 export connected { area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		braced := ospf3PackedCompile15017(t,
			"protocols { ospf3 { router-id 1.1.1.1; export connected; area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		if packed.RouterID != braced.RouterID || !reflect.DeepEqual(packed.Export, braced.Export) ||
			len(packed.Areas) != len(braced.Areas) {
			t.Errorf("packed (%q/%v areas=%d) != braced (%q/%v areas=%d) (#15017)",
				packed.RouterID, packed.Export, len(packed.Areas),
				braced.RouterID, braced.Export, len(braced.Areas))
		}
	})

	// Control: the plain packed line (already folded before the
	// compiler) must keep compiling.
	t.Run("plain packed line control", func(t *testing.T) {
		got := ospf3PackedCompile15017(t, "protocols { ospf3 router-id 1.1.1.1; }")
		checkOSPF3_15017(t, "plain packed", got, "1.1.1.1", nil, 0)
	})

	// Routing-instance mirror shares compileProtocols.
	t.Run("routing-instance packed tail with braced area", func(t *testing.T) {
		tree, perrs := NewParser(
			"routing-instances { VRF-A { protocols { ospf3 router-id 3.3.3.3 export connected { area 0.0.0.0 { interface ge-0/0/2.0; } } } } }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile rejected routing-instance fixture: %v", err)
		}
		var ri *OSPFv3Config
		for _, inst := range cfg.RoutingInstances {
			if inst != nil && inst.OSPFv3 != nil {
				ri = inst.OSPFv3
			}
		}
		if ri == nil {
			t.Fatalf("routing-instance fixture produced no OSPFv3 config: %+v", cfg.RoutingInstances)
		}
		if ri.RouterID != "3.3.3.3" || !reflect.DeepEqual(ri.Export, []string{"connected"}) || len(ri.Areas) != 1 {
			t.Errorf("routing-instance packed: rid=%q export=%v areas=%d, want 3.3.3.3/[connected]/1 (#15017)",
				ri.RouterID, ri.Export, len(ri.Areas))
		}
	})
}

// TestProtocolsPackedTopCensus15017 is the census the issue asks for:
// every `protocols <p>` top node that carries top-level leaves gets one
// mixed packed-tail+braced-body cell through the real reader, so the
// next top that starts dropping its tail fails here instead of in a
// later audit. OSPF (#14427) and IS-IS (#14426) cells are the
// already-fixed controls; RIP and OSPFv3 are this issue's fix.
func TestProtocolsPackedTopCensus15017(t *testing.T) {
	t.Run("ospf control", func(t *testing.T) {
		cfg, err := CompileConfig(hierTree(t,
			"protocols { ospf passive router-id 1.1.1.1 { area 0.0.0.0 { interface ge-0/0/0.0; } } }"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if cfg.Protocols.OSPF == nil || !cfg.Protocols.OSPF.PassiveDefault || cfg.Protocols.OSPF.RouterID != "1.1.1.1" {
			t.Errorf("ospf census cell regressed: %+v (#15017 census)", cfg.Protocols.OSPF)
		}
	})
	t.Run("isis control", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t,
			"protocols { isis wide-metrics-only authentication-key K1 { authentication-type md5; } }")
		// The braced body here is the type leaf, so the packed tail
		// (flag + key) must survive beside it — the #14426 shape.
		if cfg.Protocols.ISIS.AuthKey.Reveal() != "K1" || !cfg.Protocols.ISIS.WideMetricsOnly {
			t.Errorf("isis census cell regressed: key=%q wide=%v (#15017 census)",
				cfg.Protocols.ISIS.AuthKey.Reveal(), cfg.Protocols.ISIS.WideMetricsOnly)
		}
	})
	t.Run("rip", func(t *testing.T) {
		cfg := ripPackedCompile15017(t,
			"protocols { rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; } }")
		checkRIP15017(t, "rip census", cfg, "secret", "md5", []string{"ge-0/0/0.0"})
	})
	t.Run("ospf3", func(t *testing.T) {
		got := ospf3PackedCompile15017(t,
			"protocols { ospf3 router-id 1.1.1.1 export connected { area 0.0.0.0 { interface ge-0/0/0.0; } } }")
		checkOSPF3_15017(t, "ospf3 census", got, "1.1.1.1", []string{"connected"}, 1)
	})
}
