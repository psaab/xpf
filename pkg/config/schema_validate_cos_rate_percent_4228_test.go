package config_test

// #4228 Gap 2: CoS `transmit-rate` and `shaping-rate` accept the Junos
// `percent <n>` / `remainder` forms in addition to an absolute k/m/g rate.
//
// FAIL-ON-REVERT: with the ValueRate-only validator restored, every
// percent/remainder accept case below flips to a commit error (the head token
// "percent"/"remainder" fails ValidateRate), and the compile cases lose the
// TransmitRatePercent / ShapingRatePercent fields.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func mustCompileSet4228(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestCoSTransmitRatePercent_AcceptsAndCompiles(t *testing.T) {
	// Flat-set groups `percent 50` as a container + child; the gather helper
	// flattens it, so the compiler records the percent.
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate percent 50",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if sched.TransmitRatePercent != 50 {
		t.Fatalf("TransmitRatePercent = %v, want 50", sched.TransmitRatePercent)
	}
	if sched.TransmitRateBytes != 0 {
		t.Fatalf("TransmitRateBytes = %d, want 0 (percent form has no absolute rate)", sched.TransmitRateBytes)
	}
}

func TestCoSTransmitRatePercentExact_AcceptsAndCompiles(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate percent 30 exact",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched.TransmitRatePercent != 30 {
		t.Fatalf("TransmitRatePercent = %v, want 30", sched.TransmitRatePercent)
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected TransmitRateExact after `percent 30 exact`")
	}
}

func TestCoSTransmitRateRemainder_AcceptsAndCompiles(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate remainder",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if !sched.TransmitRateRemainder {
		t.Fatal("expected TransmitRateRemainder")
	}
	if sched.TransmitRateBytes != 0 || sched.TransmitRatePercent != 0 {
		t.Fatalf("remainder should carry no rate/percent, got bytes=%d percent=%v",
			sched.TransmitRateBytes, sched.TransmitRatePercent)
	}
}

func TestCoSTransmitRateHierarchicalPercent_Accepts(t *testing.T) {
	// The hierarchical parser packs `transmit-rate percent 50;` onto one node's
	// Keys; gatherLeafTailTokens must normalize it to the same tail.
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate percent 50;
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical `transmit-rate percent 50` rejected: %v", err)
	}
}

func TestCoSTransmitRatePlainRate_StillWorks(t *testing.T) {
	// Regression: the bare k/m/g form and exact modifier are unchanged.
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched.TransmitRateBytes != 125000000 { // 1g bits / 8
		t.Fatalf("TransmitRateBytes = %d, want 125000000", sched.TransmitRateBytes)
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected TransmitRateExact")
	}
	if sched.TransmitRatePercent != 0 || sched.TransmitRateRemainder {
		t.Fatal("plain rate must not set percent/remainder")
	}
}

func TestCoSTransmitRatePercentOutOfRange_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate percent 150")
	if err == nil {
		t.Fatal("expected error for `transmit-rate percent 150`")
	}
	if !strings.Contains(err.Error(), "percent") {
		t.Fatalf("error should reference percent: %v", err)
	}
}

func TestCoSTransmitRatePercentMissingValue_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate percent")
	if err == nil {
		t.Fatal("expected error for `transmit-rate percent` with no value")
	}
}

func TestCoSTransmitRatePercentGarbage_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate percent abc")
	if err == nil {
		t.Fatal("expected error for `transmit-rate percent abc`")
	}
}

func TestCoSShapingRatePercent_AcceptsAndCompiles(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service traffic-control-profiles p1 shaping-rate percent 90",
	)
	tcp := cfg.ClassOfService.TrafficControlProfiles["p1"]
	if tcp == nil {
		t.Fatal("expected p1 traffic-control-profile")
	}
	if tcp.ShapingRatePercent != 90 {
		t.Fatalf("ShapingRatePercent = %v, want 90", tcp.ShapingRatePercent)
	}
	if tcp.ShapingRateBytes != 0 {
		t.Fatalf("ShapingRateBytes = %d, want 0 (percent form)", tcp.ShapingRateBytes)
	}
}

func TestCoSShapingRatePlainRate_StillWorks(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service traffic-control-profiles p1 shaping-rate 10m",
	)
	tcp := cfg.ClassOfService.TrafficControlProfiles["p1"]
	if tcp.ShapingRateBytes != 1250000 { // 10m bits / 8
		t.Fatalf("ShapingRateBytes = %d, want 1250000", tcp.ShapingRateBytes)
	}
	if tcp.ShapingRatePercent != 0 {
		t.Fatal("plain rate must not set percent")
	}
}

func TestCoSShapingRateRemainder_Rejected(t *testing.T) {
	// shaping-rate has no `remainder` form.
	err := flatSchemaCheck(t, "set class-of-service traffic-control-profiles p1 shaping-rate remainder")
	if err == nil {
		t.Fatal("expected error for `shaping-rate remainder`")
	}
}

// Copilot #4320 FIX 4: a traffic-control-profile carrying BOTH an absolute
// shaping-rate and a `percent` shaping-rate (separate flat-set sibling nodes)
// must be REJECTED at compile, not silently resolved order-dependently. The
// compiler iterates ALL shaping-rate statements and merges both fields so
// validateClassOfServiceStrict catches the conflict. RED on revert: FindChild
// reads only the first statement, so bytes+percent never coexist and the
// conflict goes undetected.
func TestCoSShapingRateBytesAndPercentConflict_Rejected(t *testing.T) {
	orders := [][]string{
		{
			"set class-of-service traffic-control-profiles p1 shaping-rate 1g",
			"set class-of-service traffic-control-profiles p1 shaping-rate percent 90",
		},
		{ // reverse order must be equally rejected (order-independence)
			"set class-of-service traffic-control-profiles p1 shaping-rate percent 90",
			"set class-of-service traffic-control-profiles p1 shaping-rate 1g",
		},
	}
	for i, cmds := range orders {
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("order %d ParseSetCommand(%q): %v", i, cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("order %d SetPath(%q): %v", i, cmd, err)
			}
		}
		_, err := config.CompileConfig(tree)
		if err == nil {
			t.Fatalf("order %d: bytes+percent shaping-rate conflict was not rejected", i)
		}
		if !strings.Contains(err.Error(), "shaping-rate") {
			t.Fatalf("order %d: error should reference shaping-rate: %v", i, err)
		}
	}
}

// Advisory: a percent transmit-rate on a scheduler that is NOT bound (via a
// scheduler-map) to an interface with a root shaping-rate has no base to
// resolve against, so it stays inert and ValidateConfig flags it. #4228 Gap 2
// made the percent resolve when bound to a shaped interface (see
// TestCoSTransmitRatePercent_ResolvesAgainstInterfaceShapingRate in the Rust
// forwarding_build suite); this covers the unbound residual.
func TestCoSTransmitRatePercent_UnboundEmitsNoEffectAdvisory(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate percent 50",
	)
	warnings := config.ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "transmit-rate percent") && strings.Contains(w, "no base to resolve") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a no-effect advisory for an unbound transmit-rate percent, got: %v", warnings)
	}
}

// #4228 Gap 2: a percent transmit-rate on a scheduler that IS bound via a
// scheduler-map to a shaped interface RESOLVES — the Go control plane must NOT
// emit the unbound no-effect advisory for it. FAIL-ON-REVERT: with the
// resolution reverted the scheduler is never in the resolved set and the
// advisory fires unconditionally, so this assertion flips.
func TestCoSTransmitRatePercent_BoundToShapedInterface_NoAdvisory(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be transmit-rate percent 50",
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service scheduler-maps m1 forwarding-class best-effort scheduler be",
		"set class-of-service interfaces ge-0/0/2 unit 0 shaping-rate 100m",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map m1",
	)
	warnings := config.ValidateConfig(cfg)
	for _, w := range warnings {
		if strings.Contains(w, "transmit-rate percent") && strings.Contains(w, "no base to resolve") {
			t.Fatalf("bound-to-shaped-interface percent must not emit the no-effect advisory, got: %q", w)
		}
	}
}

// #4228 Gap 2 (shaping-rate percent, Go resolution): a `shaping-rate percent`
// traffic-control-profile bound to an interface with a configured speed
// resolves to an absolute per-unit root shaper rate. FAIL-ON-REVERT: without
// the resolveCoSTrafficControlProfiles percent branch the unit stays unshaped
// (ShapingRateBytes == 0).
func TestCoSShapingRatePercent_ResolvesAgainstInterfaceSpeed(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set interfaces ge-0/0/2 speed 10g",
		"set class-of-service traffic-control-profiles p1 shaping-rate percent 90",
		"set class-of-service interfaces ge-0/0/2 unit 0 output-traffic-control-profile p1",
	)
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	// 10g bits/s / 8 = 1_250_000_000 bytes/s; 90% = 1_125_000_000.
	if unit.ShapingRateBytes != 1_125_000_000 {
		t.Fatalf("ShapingRateBytes = %d, want 1125000000 (90%% of 10g line rate)", unit.ShapingRateBytes)
	}
}

// #4228 Gap 2: a shaping-rate percent bound to an interface with NO configured
// speed cannot resolve, so the unit is left unshaped and a per-binding advisory
// flags it.
func TestCoSShapingRatePercent_NoInterfaceSpeed_EmitsNoEffectAdvisory(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service traffic-control-profiles p1 shaping-rate percent 90",
		"set class-of-service interfaces ge-0/0/2 unit 0 output-traffic-control-profile p1",
	)
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	if unit.ShapingRateBytes != 0 {
		t.Fatalf("ShapingRateBytes = %d, want 0 (no interface speed to resolve percent against)", unit.ShapingRateBytes)
	}
	warnings := config.ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "shaping-rate percent") && strings.Contains(w, "no configured speed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a no-effect advisory for an unresolvable shaping-rate percent, got: %v", warnings)
	}
}
