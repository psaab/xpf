package config

import "testing"

// #14426 (DR16-H5): IS-IS top level, wide-metrics-only / overload first:
// trailing authentication dropped.
//
// The braced spelling
//
//	isis { wide-metrics-only; authentication-key K1; authentication-type md5; }
//
// creates child nodes the IS-IS top loop reads. The packed spelling
//
//	isis wide-metrics-only authentication-key K1 authentication-type md5;
//
// puts the whole body on the isis node's own Keys with no Children. The
// loop applied expandFlatRun to isisNode.Children (empty), so it saw
// nothing: AuthKey/AuthType and the leading flag were all lost, and FRR
// renders area-password/domain-password only when AuthKey != "" — an
// unauthenticated adjacency on a commit reporting success.
//
// The named heads are plain args:0 flags, so the fix must cover every
// first head, not just these two admission pairs.

func isisTopPackedCompile14426(t *testing.T, text string) *Config {
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

func checkISISTop14426(t *testing.T, label string, cfg *Config, wantKey, wantType string, wantWide, wantOverload bool) {
	t.Helper()
	isis := cfg.Protocols.ISIS
	if isis.AuthKey.Reveal() != wantKey {
		t.Errorf("%s: AuthKey = %q, want %q — FRR renders no area-password/domain-password (#14426)", label, isis.AuthKey.Reveal(), wantKey)
	}
	if isis.AuthType != wantType {
		t.Errorf("%s: AuthType = %q, want %q (#14426)", label, isis.AuthType, wantType)
	}
	if isis.WideMetricsOnly != wantWide {
		t.Errorf("%s: WideMetricsOnly = %v, want %v (#14426)", label, isis.WideMetricsOnly, wantWide)
	}
	if isis.Overload != wantOverload {
		t.Errorf("%s: Overload = %v, want %v (#14426)", label, isis.Overload, wantOverload)
	}
}

func TestISISPackedTopAuthDR16H5(t *testing.T) {
	const net = "net 49.0001.0000.0000.0001.00; "

	// Braced positive controls: must carry the values, or every
	// packed comparison below passes vacuously against empty fields.
	t.Run("braced controls", func(t *testing.T) {
		wide := isisTopPackedCompile14426(t,
			"protocols { isis { "+net+"wide-metrics-only; authentication-key K1; authentication-type md5; } }")
		checkISISTop14426(t, "braced wide", wide, "K1", "md5", true, false)
		over := isisTopPackedCompile14426(t,
			"protocols { isis { "+net+"overload; authentication-key K1; authentication-type md5; } }")
		checkISISTop14426(t, "braced overload", over, "K1", "md5", false, true)
	})

	// The two named packed trigger lines (hierarchical packed body on
	// the `protocols { isis …; }` container line).
	t.Run("wide-metrics-only first packed", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t,
			"protocols { isis wide-metrics-only authentication-key K1 authentication-type md5; }")
		checkISISTop14426(t, "packed wide", cfg, "K1", "md5", true, false)
	})
	t.Run("overload first packed", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t,
			"protocols { isis overload authentication-key K1 authentication-type md5; }")
		checkISISTop14426(t, "packed overload", cfg, "K1", "md5", false, true)
	})

	// Same packed run nested one level deeper (`isis { …packed…; }` is
	// the flat-run shape: statements packed onto a child line). Every
	// head keyword must preserve the full tail.
	t.Run("head-keyword matrix", func(t *testing.T) {
		tails := []struct {
			tail       string
			key, typ   string
			wide, over bool
		}{
			{"wide-metrics-only authentication-key K1 authentication-type md5", "K1", "md5", true, false},
			{"overload authentication-key K1 authentication-type md5", "K1", "md5", false, true},
			{"authentication-key K1 authentication-type md5 wide-metrics-only", "K1", "md5", true, false},
			{"authentication-type md5 authentication-key K1 overload", "K1", "md5", false, true},
			{"level level-1 authentication-key K1 authentication-type md5 wide-metrics-only", "K1", "md5", true, false},
		}
		for _, tc := range tails {
			cfg := isisTopPackedCompile14426(t,
				"protocols { isis { "+net+tc.tail+"; } }")
			checkISISTop14426(t, "matrix "+tc.tail, cfg, tc.key, tc.typ, tc.wide, tc.over)
		}
	})

	// Packed == braced, field-for-field, on the trigger spellings.
	t.Run("packed equals braced", func(t *testing.T) {
		for _, head := range []string{"wide-metrics-only", "overload"} {
			packed := isisTopPackedCompile14426(t,
				"protocols { isis "+head+" authentication-key K1 authentication-type md5; }").Protocols.ISIS
			braced := isisTopPackedCompile14426(t,
				"protocols { isis { "+head+"; authentication-key K1; authentication-type md5; } }").Protocols.ISIS
			if packed.AuthKey.Reveal() != braced.AuthKey.Reveal() || packed.AuthType != braced.AuthType ||
				packed.WideMetricsOnly != braced.WideMetricsOnly || packed.Overload != braced.Overload ||
				packed.Level != braced.Level {
				t.Errorf("head %s: packed (%q/%q wide=%v over=%v level=%q) != braced (%q/%q wide=%v over=%v level=%q) (#14426)",
					head,
					packed.AuthKey.Reveal(), packed.AuthType, packed.WideMetricsOnly, packed.Overload, packed.Level,
					braced.AuthKey.Reveal(), braced.AuthType, braced.WideMetricsOnly, braced.Overload, braced.Level)
			}
		}
	})

	// Mixed shape: a packed run line plus a separately braced interface
	// block inside the same isis container — both halves must be read.
	t.Run("mixed packed line and braced interface", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t,
			"protocols { isis { "+net+
				"wide-metrics-only authentication-key K1 authentication-type md5; "+
				"interface ge-0/0/0.0 { passive; } } }")
		checkISISTop14426(t, "mixed", cfg, "K1", "md5", true, false)
		if len(cfg.Protocols.ISIS.Interfaces) != 1 || cfg.Protocols.ISIS.Interfaces[0].Name != "ge-0/0/0.0" ||
			!cfg.Protocols.ISIS.Interfaces[0].Passive {
			t.Errorf("mixed: interfaces = %+v, want one passive ge-0/0/0.0 (#14426)", cfg.Protocols.ISIS.Interfaces)
		}
	})

	// Packed tail plus braced body on the SAME isis line: the tail ends
	// in a leaf, so packedBodyChildren declines to expand it alone; both
	// halves must still be read.
	t.Run("packed tail with braced body", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t,
			"protocols { isis wide-metrics-only authentication-key K1 { authentication-type md5; } }")
		checkISISTop14426(t, "packed+braced", cfg, "K1", "md5", true, false)
	})
	// Single-flag controls: a lone packed flag must compile, not drop.
	t.Run("single flag packed", func(t *testing.T) {
		cfg := isisTopPackedCompile14426(t, "protocols { isis overload; }")
		if !cfg.Protocols.ISIS.Overload {
			t.Errorf("single overload packed: Overload = false, want true (#14426)")
		}
		cfg = isisTopPackedCompile14426(t, "protocols { isis wide-metrics-only; }")
		if !cfg.Protocols.ISIS.WideMetricsOnly {
			t.Errorf("single wide-metrics-only packed: WideMetricsOnly = false, want true (#14426)")
		}
	})

	// Routing-instance spelling shares compileProtocols and must agree.
	t.Run("routing-instance packed", func(t *testing.T) {
		tree, perrs := NewParser(
			"routing-instances { VRF-A { protocols { isis overload authentication-key K1 authentication-type md5; } } }").Parse()
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
		if riISIS == nil {
			t.Fatalf("routing-instance fixture produced no IS-IS config: %+v", cfg.RoutingInstances)
		}
		if riISIS.AuthKey.Reveal() != "K1" || riISIS.AuthType != "md5" || !riISIS.Overload {
			t.Errorf("routing-instance packed: key=%q type=%q overload=%v, want K1/md5/true (#14426)",
				riISIS.AuthKey.Reveal(), riISIS.AuthType, riISIS.Overload)
		}
	})
}
