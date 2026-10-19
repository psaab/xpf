package config

import (
	"strings"
	"testing"
)

// #6847 made `class-of-service classifiers inet-precedence` a LIVE
// behavior-aggregate classifier: it compiles, crosses the wire, and the
// dataplane selects the egress queue and loss-priority from the top 3 bits of
// the DS field. Four review follow-ups were filed because the surfaces around
// it were not extended with it. These are the two compiler-side ones.

func cosINetTree7080(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// cosINetTree7080Lenient is the tolerant-path twin, for fixtures that
// DELIBERATELY carry a dangling class-of-service interface reference.
//
// #7337 made those references a hard commit error, so a fixture built to
// exercise the WARNING must compile on the path where a warning is still what
// happens. Loosening the shared strict helper instead would silently remove
// the strict check from every other test in this file — those tests would keep
// passing while no longer proving anything about commit behaviour.
func cosINetTree7080Lenient(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// #7084: the collector accepted DECIMAL 0..7 only, so the two spellings Junos
// actually uses were rejected at commit.
//
// The binary rows are the ones that CHANGE behaviour. `000` and `001` mean 0
// and 1 under either reading, so they are controls: they prove the widening did
// not break the decimal path. `010` and up are 10, 11, 100... in decimal, all
// out of range and rejected before this change, so each is a config that did
// not commit and now does.
func TestINetPrecedenceCodePointSpellings_7084(t *testing.T) {
	for _, tc := range []struct {
		token string
		want  uint8
	}{
		{"0", 0}, {"7", 7}, // decimal, unchanged
		{"000", 0}, {"001", 1}, // binary == decimal here: controls
		{"010", 2}, {"011", 3}, {"100", 4}, {"101", 5}, {"110", 6}, {"111", 7},
		{"routine", 0}, {"priority", 1}, {"immediate", 2}, {"flash", 3},
		{"flash-override", 4}, {"critical-ecp", 5}, {"internet-control", 6},
		{"net-control", 7},
	} {
		t.Run(tc.token, func(t *testing.T) {
			cfg := cosINetTree7080(t,
				"set class-of-service forwarding-classes queue 0 BE",
				"set class-of-service classifiers inet-precedence C forwarding-class BE loss-priority low code-points "+tc.token,
			)
			def := cfg.ClassOfService.INetPrecedenceClassifierDefs["C"]
			if def == nil || len(def.Entries) == 0 {
				t.Fatalf("code-point %q produced no classifier entry", tc.token)
			}
			got := def.Entries[0].Precedences
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("code-point %q compiled to %v, want [%d]", tc.token, got, tc.want)
			}
		})
	}
}

// The rejection side. Widening must not turn the collector into "accept
// anything" — a typo has to stay a loud commit failure, which is what the
// pre-existing behaviour got right and is the only thing #7084 did not want
// changed.
func TestINetPrecedenceRejectsNonsense_7084(t *testing.T) {
	for _, token := range []string{
		"8",        // decimal, out of range
		"1111",     // four bits: not a 3-bit spelling, and 1111 decimal is out of range
		"11",       // two chars: decimal 11, out of range — NOT binary 3
		"routine2", // near-miss alias
		"cs7",      // a DSCP alias, not an IP-precedence one
	} {
		t.Run(token, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, ln := range []string{
				"set class-of-service forwarding-classes queue 0 BE",
				"set class-of-service classifiers inet-precedence C forwarding-class BE loss-priority low code-points " + token,
			} {
				path, err := ParseSetCommand(ln)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", ln, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", ln, err)
				}
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Errorf("code-point %q was ACCEPTED; a typo must stay a loud commit rejection", token)
			}
		})
	}
}

// #7081: every OTHER CoS binding a unit can carry drew an undefined-reference
// warning; the one #6847 added did not.
func TestUndefinedINetPrecedenceClassifierWarns_7081(t *testing.T) {
	// #7337 made a dangling class-of-service interface reference a hard commit
	// error, so this fixture compiles on the TOLERANT path — the one where the
	// warning under test is still the outcome. The warning itself is unchanged.
	cfg := cosINetTree7080Lenient(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence NOPE",
	)
	if !cosHasWarning7080(ValidateConfig(cfg), `undefined inet-precedence classifier "NOPE"`) {
		t.Errorf("a dangling inet-precedence binding drew no warning; warnings=%v", ValidateConfig(cfg))
	}
}

// The other polarity, and the subtlety that decides WHICH field means
// "defined": the warning keys on INetPrecedenceClassifiers, the NAME list.
// #15681 populates INetPrecedenceClassifierDefs unconditionally, but a
// classifier defined with a body that compiles to nothing still has zero
// entries — keying the warning on entry-bearing Defs would report
// "references undefined ... classifier" for a classifier the operator can
// see in their own config — a confident wrong name.
func TestDefinedINetPrecedenceClassifierDoesNotWarn_7081(t *testing.T) {
	t.Run("with entries", func(t *testing.T) {
		cfg := cosINetTree7080(t,
			"set class-of-service forwarding-classes queue 0 BE",
			"set class-of-service classifiers inet-precedence REAL forwarding-class BE loss-priority low code-points 5",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence REAL",
		)
		if cosHasWarning7080(ValidateConfig(cfg), "undefined inet-precedence classifier") {
			t.Errorf("a DEFINED classifier drew an undefined-reference warning; warnings=%v", ValidateConfig(cfg))
		}
	})
	t.Run("defined but no entries", func(t *testing.T) {
		cfg := cosINetTree7080(t,
			"set class-of-service classifiers inet-precedence EMPTY",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence EMPTY",
		)
		// #15681: Defs is now populated unconditionally, so EMPTY is present
		// with zero entries — the definedness distinction this subtest pins
		// is that the warning keys on the name list, not on entry count.
		if def := cfg.ClassOfService.INetPrecedenceClassifierDefs["EMPTY"]; def == nil || len(def.Entries) != 0 {
			t.Fatalf("fixture is wrong: EMPTY should be in Defs with no entries after #15681, got %#v", def)
		}
		if cosHasWarning7080(ValidateConfig(cfg), "undefined inet-precedence classifier") {
			t.Errorf("a classifier defined with no entries was reported as UNDEFINED — the warning is "+
				"keyed on the Defs map rather than the name list (#7081); warnings=%v", ValidateConfig(cfg))
		}
	})
}

// #7082: classOfServiceClassifierQueueWarnings' own doc says its model mirrors
// build_cos_iface_config "exactly so the warning fires iff the dataplane would
// have blackholed the code-point". With only the dscp and ieee-802.1 arms that
// sentence was false for every unit whose blackholing classifier was the
// inet-precedence one.
//
// The fixture names a DEFINED forwarding-class whose queue the interface does
// not materialize, which is the #hb166 T-4 shape. The scheduler-map resolves
// (so the interface IS admitted to CoS) but covers a different class.
func TestINetPrecedenceBlackholeWarns_7082(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set class-of-service forwarding-classes queue 5 VOICE",
		"set class-of-service schedulers S transmit-rate percent 10",
		"set class-of-service scheduler-maps M forwarding-class BE scheduler S",
		"set class-of-service classifiers inet-precedence PREC forwarding-class VOICE loss-priority low code-points 5",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 scheduler-map M",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence PREC",
	)
	if !cosHasWarning7080(ValidateConfig(cfg), `forwarding-class "VOICE"`) {
		t.Errorf("an inet-precedence classifier mapping to an unmaterialized queue drew no blackhole "+
			"warning, so the T-4 model does not mirror build_cos_iface_config (#7082); warnings=%v",
			ValidateConfig(cfg))
	}
}

// The control: the same shape with the class MATERIALIZED must stay silent, or
// the arm would be "correct" by warning unconditionally.
func TestINetPrecedenceMaterializedDoesNotWarn_7082(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 5 VOICE",
		"set class-of-service schedulers S transmit-rate percent 10",
		"set class-of-service scheduler-maps M forwarding-class VOICE scheduler S",
		"set class-of-service classifiers inet-precedence PREC forwarding-class VOICE loss-priority low code-points 5",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 scheduler-map M",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence PREC",
	)
	if cosHasWarning7080(ValidateConfig(cfg), `forwarding-class "VOICE"`) {
		t.Errorf("a MATERIALIZED class drew a blackhole warning; warnings=%v", ValidateConfig(cfg))
	}
}

func cosHasWarning7080(warnings []string, needle string) bool {
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	return false
}
