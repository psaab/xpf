package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// #16714: the single-rate `firewall policer` burst floor was 1500 (L3
// bytes, #10310) while the userspace meter charges the full Ethernet
// frame (1500-byte MTU payload + 14-byte header = 1514 untagged, #8581).
// burst-size-limit 1500..1513 therefore committed clean and dropped
// every full-size frame. #17760: the floor must also admit a maximum
// 802.1Q-tagged frame at the default MTU: 1500 MTU + 14-byte Ethernet
// header + 4-byte VLAN tag = 1518 bytes. The floor is now the shared
// minPolicerBurstBytes16714 (1518) enforced by the schema validator and
// the strict compiled-config gate; tolerant load warns.
//
// FAIL-ON-REVERT: reverting minPolicerBurstBytes16714 to 1514 (or
// dropping the floor check in ValidatePolicerBurstSize /
// validateFirewallPolicerLimitsStrict) makes the 1514..1517 rows pass.

func TestPolicerBurstFloor16714SchemaRejectsSubFrame(t *testing.T) {
	for _, value := range []string{"1500", "1513", "1514", "1517", "1k"} {
		err := policer5299SchemaCheck(t,
			"set firewall policer p1 if-exceeding burst-size-limit "+value)
		if err == nil {
			t.Errorf("burst-size-limit %s: SchemaValidate accepted sub-frame burst", value)
			continue
		}
		if !strings.Contains(err.Error(), "maximum-sized frame") || !strings.Contains(err.Error(), "1518") {
			t.Errorf("burst-size-limit %s: error should name the 1518-byte frame floor, got: %v", value, err)
		}
		if !strings.Contains(err.Error(), "burst-size-limit") {
			t.Errorf("burst-size-limit %s: error should name leaf path, got: %v", value, err)
		}
	}
	// Twin at the floor is accepted.
	if err := policer5299SchemaCheck(t,
		"set firewall policer p1 if-exceeding burst-size-limit 1518"); err != nil {
		t.Errorf("burst-size-limit 1518: SchemaValidate rejected floor twin: %v", err)
	}
	// Shared constant: the three-color validator rejects the same values.
	if err := validateThreeColorPolicerBurstSize11827("1500"); err == nil {
		t.Errorf("three-color burst 1500: expected shared-floor rejection")
	}
	if got := minPolicerBurstBytes16714; got != 1518 {
		t.Errorf("minPolicerBurstBytes16714 = %d, want 1518 (shared frame floor)", got)
	}
}

func TestPolicerBurstFloor16714StrictGate(t *testing.T) {
	reject := []string{"1500", "1513", "1514", "1517", "1000", "64"}
	for _, burst := range reject {
		t.Run("reject/"+burst, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, []string{
				"set firewall policer p1 if-exceeding bandwidth-limit 1m",
				"set firewall policer p1 if-exceeding burst-size-limit " + burst,
				"set firewall policer p1 then discard",
			}))
			if err == nil {
				t.Fatalf("CompileConfig accepted sub-frame burst-size-limit %s", burst)
			}
			if !strings.Contains(err.Error(), "maximum-sized frame") {
				t.Fatalf("error should contain maximum-sized frame, got: %v", err)
			}
		})
	}
	t.Run("accept/1518", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set firewall policer p1 if-exceeding bandwidth-limit 1m",
			"set firewall policer p1 if-exceeding burst-size-limit 1518",
			"set firewall policer p1 then discard",
		}))
		if err != nil {
			t.Fatalf("CompileConfig rejected floor twin: %v", err)
		}
		pol := cfg.Firewall.Policers["p1"]
		if pol == nil || pol.BurstSizeLimit != 1518 {
			t.Fatalf("floor twin compiled changed: %+v", pol)
		}
	})
	// Direct gate: a compiled sub-frame burst fails even when the
	// schema leaf was bypassed (defense in depth for programmatic trees).
	pol := &PolicerConfig{Name: "p1", BandwidthLimit: 125000, BurstSizeLimit: 1500}
	if err := validateFirewallPolicerLimitsStrict(singleRateCfg16714(pol)); err == nil ||
		!strings.Contains(err.Error(), "maximum-sized frame") {
		t.Fatalf("direct gate must reject sub-frame burst, got: %v", err)
	}
}

func singleRateCfg16714(pol *PolicerConfig) *Config {
	cfg := &Config{}
	cfg.Firewall.Policers = map[string]*PolicerConfig{pol.Name: pol}
	return cfg
}

func TestPolicerBurstFloor16714LenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall policer p1 if-exceeding bandwidth-limit 1m",
		"set firewall policer p1 if-exceeding burst-size-limit 1500",
		"set firewall policer p1 then discard",
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
	// Lenient path still preserves the compiled value (no silent clamp).
	pol := cfg.Firewall.Policers["p1"]
	if pol == nil || pol.BurstSizeLimit != 1500 {
		t.Fatalf("lenient compile should preserve sub-frame burst, got: %+v", pol)
	}
	// Missing-limit lenient behaviour is unchanged: a policer with no
	// burst at all still warns (missing, not floor) and boots.
	tree2 := buildTree(t, []string{
		"set firewall policer p2 if-exceeding bandwidth-limit 1m",
		"set firewall policer p2 then discard",
	})
	cfg2, err := CompileConfigLenient(tree2)
	if err != nil {
		t.Fatalf("lenient compile must not brick on missing burst, got: %v", err)
	}
	foundMissing := false
	for _, w := range cfg2.Warnings {
		if strings.Contains(w, "missing limits") {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("lenient compile should warn on missing limits, warnings: %v", cfg2.Warnings)
	}
}

type policerDefect17761 struct {
	name string
	kind string
}

func expectedLenientPolicerWarning17761(d policerDefect17761) string {
	switch d.kind {
	case "floor":
		return fmt.Sprintf("firewall policer burst floor (downgraded to warning on tolerant path; the sub-1518-byte bucket drops every maximum-sized VLAN frame): firewall policer %q burst-size-limit must be at least one maximum-sized frame (1518 bytes: 1500-byte MTU + 14-byte Ethernet header + 4-byte VLAN tag), got 1500", d.name)
	case "missing-bandwidth":
		return fmt.Sprintf("firewall policer missing limits (downgraded to warning on tolerant path): firewall policer %q requires `if-exceeding bandwidth-limit` (missing bandwidth-limit compiles to a 0-rate policer that drops all policed traffic)", d.name)
	case "missing-burst":
		return fmt.Sprintf("firewall policer missing limits (downgraded to warning on tolerant path): firewall policer %q requires `if-exceeding burst-size-limit` (missing burst-size-limit compiles to a 0-burst policer that drops all policed traffic)", d.name)
	default:
		panic("unexpected policer defect class: " + d.kind)
	}
}

func TestPolicerLimitsLenientClassifiesAllDefectClasses17761(t *testing.T) {
	// Each defect list is in sorted policer-name order, which pins the exact
	// warning sequence independently of which defect class sorts first.
	cases := []struct {
		name    string
		defects []policerDefect17761
	}{
		{
			name: "floor error sorts first",
			defects: []policerDefect17761{
				{name: "a", kind: "floor"},
				{name: "b", kind: "missing-bandwidth"},
				{name: "c", kind: "missing-burst"},
			},
		},
		{
			name: "missing bandwidth sorts first",
			defects: []policerDefect17761{
				{name: "a", kind: "missing-bandwidth"},
				{name: "b", kind: "floor"},
				{name: "c", kind: "missing-burst"},
			},
		},
		{
			name: "missing burst sorts first",
			defects: []policerDefect17761{
				{name: "a", kind: "missing-burst"},
				{name: "b", kind: "missing-bandwidth"},
				{name: "c", kind: "floor"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			for _, d := range tc.defects {
				switch d.kind {
				case "floor":
					lines = append(lines,
						"set firewall policer "+d.name+" if-exceeding bandwidth-limit 1m",
						"set firewall policer "+d.name+" if-exceeding burst-size-limit 1500",
					)
				case "missing-bandwidth":
					lines = append(lines,
						"set firewall policer "+d.name+" if-exceeding burst-size-limit 1518",
					)
				case "missing-burst":
					lines = append(lines,
						"set firewall policer "+d.name+" if-exceeding bandwidth-limit 1m",
					)
				default:
					t.Fatalf("unknown test defect class %q", d.kind)
				}
				lines = append(lines, "set firewall policer "+d.name+" then discard")
			}
			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatalf("lenient compile must warn instead of bricking on all three defects: %v", err)
			}
			wantWarnings := make([]string, 0, len(tc.defects))
			for _, d := range tc.defects {
				wantWarnings = append(wantWarnings, expectedLenientPolicerWarning17761(d))
			}
			if !slices.Equal(cfg.Warnings, wantWarnings) {
				t.Fatalf("lenient compile warning sequence mismatch:\nwant: %q\ngot:  %q", wantWarnings, cfg.Warnings)
			}
		})
	}
}

func TestPolicerLimitsLenientReportsSamePolicerFloorAndMissingBandwidth17761(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set firewall policer a if-exceeding burst-size-limit 1500",
		"set firewall policer a then discard",
	}))
	if err != nil {
		t.Fatalf("lenient compile must warn instead of bricking: %v", err)
	}
	wantWarnings := []string{
		expectedLenientPolicerWarning17761(policerDefect17761{name: "a", kind: "missing-bandwidth"}),
		expectedLenientPolicerWarning17761(policerDefect17761{name: "a", kind: "floor"}),
	}
	if !slices.Equal(cfg.Warnings, wantWarnings) {
		t.Fatalf("lenient compile warning sequence mismatch:\nwant: %q\ngot:  %q", wantWarnings, cfg.Warnings)
	}
}
