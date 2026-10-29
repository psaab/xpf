package config

import (
	"strings"
	"testing"
)

// #16610: three-color burst buckets below one maximum-sized frame commit
// clean and colour every full-size frame Red (the meter charges frame
// bytes, meta.pkt_len). #17760: a maximum-size VLAN frame at a 1500 MTU
// costs 1500 + 14-byte Ethernet header + 4-byte 802.1Q tag = 1518.
// The schema validator and strict compiler gate share the 1518-byte
// floor; tolerant load warns instead of bricking.
//
// FAIL-ON-REVERT: reverting the floor in
// validateThreeColorPolicerBurstSize11827 makes the SchemaValidate
// sub-floor rows pass; reverting validateThreeColorBurstFloor16610 makes
// the direct CompileConfig rows pass.

func compileThreeColor16610(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := buildTree(t, lines)
	return CompileConfig(tree)
}

func TestThreeColorBurstFloor16610SchemaRejectsSubFrame(t *testing.T) {
	leaves := []struct{ mode, leaf string }{
		{"single-rate", "committed-burst-size"},
		{"single-rate", "excess-burst-size"},
		{"two-rate", "committed-burst-size"},
		{"two-rate", "peak-burst-size"},
	}
	for _, tc := range leaves {
		for _, value := range []string{"64", "1000", "1500", "1513", "1514", "1517", "1k"} {
			tree := flatTreeFromSets(t, threeColorPolicerSet11827(tc.mode, tc.leaf, value))
			err := SchemaValidate(tree)
			if err == nil {
				t.Errorf("%s %s %s: SchemaValidate accepted sub-frame burst", tc.mode, tc.leaf, value)
				continue
			}
			if !strings.Contains(err.Error(), "maximum-sized frame") || !strings.Contains(err.Error(), "1518") {
				t.Errorf("%s %s %s: error should name the 1518-byte frame floor, got: %v", tc.mode, tc.leaf, value, err)
			}
			if !strings.Contains(err.Error(), "firewall three-color-policer p1 "+tc.mode+" "+tc.leaf) {
				t.Errorf("%s %s %s: error should name leaf path, got: %v", tc.mode, tc.leaf, value, err)
			}
		}
		// Twin at the floor is accepted.
		tree := flatTreeFromSets(t, threeColorPolicerSet11827(tc.mode, tc.leaf, "1518"))
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("%s %s 1518: SchemaValidate rejected floor twin: %v", tc.mode, tc.leaf, err)
		}
	}
}

func TestThreeColorBurstFloor16610StrictGate(t *testing.T) {
	reject := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name: "single-rate both below floor (probe row: 1000/1000)",
			lines: []string{
				"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 single-rate committed-burst-size 1000",
				"set firewall three-color-policer p1 single-rate excess-burst-size 1000",
				"set firewall three-color-policer p1 then discard",
			},
			want: "maximum-sized frame",
		},
		{
			name: "single-rate 64/64",
			lines: []string{
				"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 single-rate committed-burst-size 64",
				"set firewall three-color-policer p1 single-rate excess-burst-size 64",
				"set firewall three-color-policer p1 then discard",
			},
			want: "maximum-sized frame",
		},
		{
			name: "two-rate peak below floor (probe row: 1k PBS)",
			lines: []string{
				"set firewall three-color-policer p1 two-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 two-rate committed-burst-size 1518",
				"set firewall three-color-policer p1 two-rate peak-information-rate 2m",
				"set firewall three-color-policer p1 two-rate peak-burst-size 1k",
				"set firewall three-color-policer p1 then discard",
			},
			want: "peak-burst-size",
		},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileThreeColor16610(t, tc.lines...)
			if err == nil {
				t.Fatalf("CompileConfig accepted sub-frame burst: %v", tc.lines)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should contain %q, got: %v", tc.want, err)
			}
		})
	}

	accept := []struct {
		name  string
		lines []string
	}{
		{
			name: "single-rate twin at floor",
			lines: []string{
				"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 single-rate committed-burst-size 1518",
				"set firewall three-color-policer p1 single-rate excess-burst-size 1518",
				"set firewall three-color-policer p1 then discard",
			},
		},
		{
			// srTCM: a large EBS rescues a frame as Yellow even if CBS is
			// sub-frame, so CBS=1000 with EBS at/above the floor is not a
			// guaranteed-Red size filter and stays valid at compile.
			// (The schema leaf still rejects a literal sub-floor CBS at
			// commit; this row exercises the compiled gate directly.)
			name: "two-rate twin at floor",
			lines: []string{
				"set firewall three-color-policer p1 two-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 two-rate committed-burst-size 1518",
				"set firewall three-color-policer p1 two-rate peak-information-rate 2m",
				"set firewall three-color-policer p1 two-rate peak-burst-size 1518",
				"set firewall three-color-policer p1 then discard",
			},
		},
	}
	for _, tc := range accept {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileThreeColor16610(t, tc.lines...); err != nil {
				t.Fatalf("CompileConfig rejected floor twin: %v", err)
			}
		})
	}

	// Direct gate: sub-frame CBS rescued by a large EBS (max semantics).
	pol := &ThreeColorPolicerConfig{Name: "p1", CIR: 125000, CBS: 1000, PBS: 15000}
	if err := validateThreeColorPolicersStrict(map[string]*ThreeColorPolicerConfig{"p1": pol}); err != nil {
		t.Fatalf("single-rate CBS<EBS with EBS above floor must pass strict gate, got: %v", err)
	}
	// Direct gate: two-rate PBS below floor fails even with CBS at floor.
	pol2 := &ThreeColorPolicerConfig{Name: "p1", TwoRate: true, CIR: 125000, CBS: 1518, PIR: 250000, PBS: 1000}
	if err := validateThreeColorPolicersStrict(map[string]*ThreeColorPolicerConfig{"p1": pol2}); err == nil ||
		!strings.Contains(err.Error(), "peak-burst-size") {
		t.Fatalf("two-rate sub-frame PBS must fail strict gate, got: %v", err)
	}
}

func TestThreeColorBurstFloor16610LenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer p1 single-rate committed-burst-size 1000",
		"set firewall three-color-policer p1 single-rate excess-burst-size 1000",
		"set firewall three-color-policer p1 then discard",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on sub-frame burst (#1960), got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "burst floor") && strings.Contains(w, "maximum-sized frame") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile should warn on burst floor, warnings: %v", cfg.Warnings)
	}
	// Lenient path still preserves the compiled values (no silent clamp).
	pol := cfg.Firewall.ThreeColorPolicers["p1"]
	if pol == nil || pol.CBS != 1000 || pol.PBS != 1000 {
		t.Fatalf("lenient compile should preserve sub-frame bursts, got: %+v", pol)
	}
}

func TestThreeColorBurstFloor16610LenientKeepsStructuralErrors(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name: "absent PIR",
			lines: []string{
				"set firewall three-color-policer p1 two-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 two-rate committed-burst-size 1000",
				"set firewall three-color-policer p1 two-rate peak-burst-size 1000",
				"set firewall three-color-policer p1 then discard",
			},
			want: `"p1" requires positive peak-information-rate`,
		},
		{
			name: "PIR below CIR",
			lines: []string{
				"set firewall three-color-policer p1 two-rate committed-information-rate 2m",
				"set firewall three-color-policer p1 two-rate committed-burst-size 1000",
				"set firewall three-color-policer p1 two-rate peak-information-rate 1m",
				"set firewall three-color-policer p1 two-rate peak-burst-size 1000",
				"set firewall three-color-policer p1 then discard",
			},
			want: "peak-information-rate must be >= committed-information-rate",
		},
		{
			name: "PBS below CBS",
			lines: []string{
				"set firewall three-color-policer p1 two-rate committed-information-rate 1m",
				"set firewall three-color-policer p1 two-rate committed-burst-size 1518",
				"set firewall three-color-policer p1 two-rate peak-information-rate 2m",
				"set firewall three-color-policer p1 two-rate peak-burst-size 1000",
				"set firewall three-color-policer p1 then discard",
			},
			want: "peak-burst-size must be >= committed-burst-size",
		},
		{
			name: "floor-only policer before structural defect",
			lines: []string{
				"set firewall three-color-policer a-floor-only two-rate committed-information-rate 1m",
				"set firewall three-color-policer a-floor-only two-rate committed-burst-size 1000",
				"set firewall three-color-policer a-floor-only two-rate peak-information-rate 2m",
				"set firewall three-color-policer a-floor-only two-rate peak-burst-size 1000",
				"set firewall three-color-policer a-floor-only then discard",
				"set firewall three-color-policer z-invalid two-rate committed-information-rate 1m",
				"set firewall three-color-policer z-invalid two-rate committed-burst-size 1000",
				"set firewall three-color-policer z-invalid two-rate peak-burst-size 1000",
				"set firewall three-color-policer z-invalid then discard",
			},
			want: `"z-invalid" requires positive peak-information-rate`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// FAIL-ON-REVERT: the old first-error downgrade accepted these
			// cases with only a floor warning and never surfaced the structural defect.
			_, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("lenient compile must preserve structural error %q despite the burst-floor violation, got: %v", tc.want, err)
			}
		})
	}
}
