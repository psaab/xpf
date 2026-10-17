package config

import "testing"

// #14410 (DR13-H3): IS-IS per-interface authentication-key /
// authentication-type dropped on a packed interface line.
//
// The braced spelling
//
//	interface ge-0/0/0.0 { passive; authentication-key K; authentication-type md5; }
//
// creates child nodes the IS-IS interface loop reads. The packed spelling
//
//	interface ge-0/0/0.0 passive authentication-key K authentication-type md5;
//
// puts the whole tail on the interface node's own Keys with no Children.
// The loop read only child.Children (via expandFlatRun) plus a Keys[2:]
// shim recognising only passive/level, so the credentials were silently
// dropped: the interface compiled with AuthKey=="" / AuthType=="" while
// `ip router isis` still rendered, forming an unauthenticated adjacency.
//
// The #8662 fold cannot rescue this: it is keyed on the FIRST tail
// token, and `passive` is not a scoped interface pair, so a leading
// `passive` strands the entire run. Fixture B covers the second rescue
// failure: a scoped head (authentication-key first) declined because a
// following router-level authentication-key sibling trips #8880.

func isisPackedAuthCompile14410(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected fixture: %v", err)
	}
	if cfg == nil || cfg.Protocols.ISIS == nil {
		t.Fatalf("fixture produced no IS-IS config")
	}
	return cfg
}

func isisPackedAuthIface14410(t *testing.T, cfg *Config) *ISISInterface {
	t.Helper()
	if len(cfg.Protocols.ISIS.Interfaces) != 1 {
		t.Fatalf("want exactly one IS-IS interface, got %+v", cfg.Protocols.ISIS.Interfaces)
	}
	return cfg.Protocols.ISIS.Interfaces[0]
}

func TestISISInterfacePackedAuthDR13H3(t *testing.T) {
	const net = "net 49.0001.0000.0000.0001.00; "

	braced := isisPackedAuthCompile14410(t,
		"protocols { isis { "+net+
			"interface ge-0/0/0.0 { passive; authentication-key IFACEKEY; authentication-type md5; metric 10; level 2; } } }")
	control := isisPackedAuthIface14410(t, braced)
	// Positive control: the braced spelling must carry the values, or
	// every comparison below passes vacuously against empty fields.
	if control.AuthKey.Reveal() != "IFACEKEY" || control.AuthType != "md5" ||
		!control.Passive || control.Metric != 10 || control.Level != "2" {
		t.Fatalf("braced control incomplete: %+v (key %q)", control, control.AuthKey.Reveal())
	}

	// Fixture A: unscoped head (`passive`) strands the whole packed run.
	t.Run("passive-first packed", func(t *testing.T) {
		cfg := isisPackedAuthCompile14410(t,
			"protocols { isis { "+net+
				"interface ge-0/0/0.0 passive authentication-key IFACEKEY authentication-type md5; } }")
		got := isisPackedAuthIface14410(t, cfg)
		if got.AuthKey.Reveal() != "IFACEKEY" {
			t.Errorf("packed passive-first: AuthKey = %q, want IFACEKEY — circuit renders without `isis password` (#14410)", got.AuthKey.Reveal())
		}
		if got.AuthType != "md5" {
			t.Errorf("packed passive-first: AuthType = %q, want md5 (#14410)", got.AuthType)
		}
		if !got.Passive {
			t.Errorf("packed passive-first: Passive = false, want true")
		}
	})

	// Fixture B: scoped head but the fold declines because a following
	// router-level authentication-key sibling shares the keyword.
	t.Run("scoped head with router-level sibling", func(t *testing.T) {
		cfg := isisPackedAuthCompile14410(t,
			"protocols { isis { "+net+
				"interface ge-0/0/0.0 authentication-key IFACEKEY authentication-type md5; "+
				"authentication-key ROUTERKEY; authentication-type md5; } }")
		got := isisPackedAuthIface14410(t, cfg)
		if got.AuthKey.Reveal() != "IFACEKEY" {
			t.Errorf("packed scoped-head: interface AuthKey = %q, want IFACEKEY (#14410)", got.AuthKey.Reveal())
		}
		if got.AuthType != "md5" {
			t.Errorf("packed scoped-head: interface AuthType = %q, want md5 (#14410)", got.AuthType)
		}
		if cfg.Protocols.ISIS.AuthKey.Reveal() != "ROUTERKEY" {
			t.Errorf("router-level AuthKey = %q, want ROUTERKEY (sibling must not be consumed by interface)", cfg.Protocols.ISIS.AuthKey.Reveal())
		}
	})

	// Every interface head keyword: packed must compile identically to
	// braced for the full tail, whatever leaf leads the run.
	t.Run("head-keyword matrix", func(t *testing.T) {
		tails := []string{
			"passive authentication-key IFACEKEY authentication-type md5",
			"authentication-key IFACEKEY authentication-type md5 passive",
			"authentication-type md5 authentication-key IFACEKEY passive",
			"metric 10 authentication-key IFACEKEY authentication-type md5",
			"level 2 authentication-key IFACEKEY authentication-type md5",
			"authentication-key IFACEKEY authentication-type md5 metric 10 level 2 passive",
		}
		for _, tail := range tails {
			cfg := isisPackedAuthCompile14410(t,
				"protocols { isis { "+net+"interface ge-0/0/0.0 "+tail+"; } }")
			got := isisPackedAuthIface14410(t, cfg)
			if got.AuthKey.Reveal() != "IFACEKEY" || got.AuthType != "md5" {
				t.Errorf("tail %q: AuthKey=%q AuthType=%q, want IFACEKEY/md5 (#14410)",
					tail, got.AuthKey.Reveal(), got.AuthType)
			}
		}
	})

	// Mixed shape: packed tail plus a braced body on the same line —
	// both halves must be read (compact_tail.go:281-285 contract).
	t.Run("mixed packed tail and braced children", func(t *testing.T) {
		cfg := isisPackedAuthCompile14410(t,
			"protocols { isis { "+net+
				"interface ge-0/0/0.0 passive authentication-key IFACEKEY { authentication-type md5; } } }")
		got := isisPackedAuthIface14410(t, cfg)
		if got.AuthKey.Reveal() != "IFACEKEY" {
			t.Errorf("mixed: AuthKey = %q, want IFACEKEY (#14410)", got.AuthKey.Reveal())
		}
		if got.AuthType != "md5" {
			t.Errorf("mixed: AuthType = %q, want md5 (#14410)", got.AuthType)
		}
		if !got.Passive {
			t.Errorf("mixed: Passive = false, want true")
		}
	})

	// Routing-instance spelling shares compileProtocols and must agree.
	t.Run("routing-instance packed", func(t *testing.T) {
		tree, perrs := NewParser(
			"routing-instances { VRF-A { protocols { isis { " + net +
				"interface ge-0/0/0.0 passive authentication-key IFACEKEY authentication-type md5; } } } }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile rejected routing-instance fixture: %v", err)
		}
		var riISIS *ISISConfig
		for _, ri := range cfg.RoutingInstances {
			if ri != nil && ri.ISIS != nil {
				riISIS = ri.ISIS
			}
		}
		if riISIS == nil || len(riISIS.Interfaces) != 1 {
			t.Fatalf("routing-instance fixture produced no single IS-IS interface: %+v", cfg.RoutingInstances)
		}
		got := riISIS.Interfaces[0]
		if got.AuthKey.Reveal() != "IFACEKEY" || got.AuthType != "md5" || !got.Passive {
			t.Errorf("routing-instance packed: got key=%q type=%q passive=%v, want IFACEKEY/md5/true (#14410)",
				got.AuthKey.Reveal(), got.AuthType, got.Passive)
		}
	})
}
